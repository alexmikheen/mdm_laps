package vault

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/1password/onepassword-sdk-go"
)

func overview(id, title string, updated time.Time) onepassword.ItemOverview {
	return onepassword.ItemOverview{ID: id, Title: title, UpdatedAt: updated}
}

func day(d int) time.Time {
	return time.Date(2026, 8, d, 0, 0, 0, 0, time.UTC)
}

func TestPickNewestMatch(t *testing.T) {
	tests := []struct {
		name        string
		items       []onepassword.ItemOverview
		serial      string
		wantID      string
		wantMatches int
	}{
		{
			name:   "no item for this device",
			items:  []onepassword.ItemOverview{overview("a", "OTHER1", day(1))},
			serial: "SERIAL1", wantID: "", wantMatches: 0,
		},
		{
			name:   "single match",
			items:  []onepassword.ItemOverview{overview("a", "SERIAL1", day(1))},
			serial: "SERIAL1", wantID: "a", wantMatches: 1,
		},
		{
			// Observed in production: a single serial can accumulate several items with
			// different passwords. Taking the first match can hand back a months-old password.
			name: "duplicates: newest wins even when it is last",
			items: []onepassword.ItemOverview{
				overview("stale", "SERIAL1", day(1)),
				overview("older", "SERIAL1", day(3)),
				overview("newest", "SERIAL1", day(9)),
			},
			serial: "SERIAL1", wantID: "newest", wantMatches: 3,
		},
		{
			name: "duplicates: newest wins even when it is first",
			items: []onepassword.ItemOverview{
				overview("newest", "SERIAL1", day(9)),
				overview("stale", "SERIAL1", day(1)),
			},
			serial: "SERIAL1", wantID: "newest", wantMatches: 2,
		},
		{
			name: "other serials are ignored",
			items: []onepassword.ItemOverview{
				overview("other-newer", "SERIAL2", day(30)),
				overview("mine", "SERIAL1", day(2)),
			},
			serial: "SERIAL1", wantID: "mine", wantMatches: 1,
		},
		{
			name:   "title is matched case-insensitively and trimmed",
			items:  []onepassword.ItemOverview{overview("a", "  serial1 ", day(1))},
			serial: "SERIAL1", wantID: "a", wantMatches: 1,
		},
		{
			name:   "empty vault",
			items:  nil,
			serial: "SERIAL1", wantID: "", wantMatches: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, matches := pickNewestMatch(tt.items, tt.serial)
			if id != tt.wantID {
				t.Errorf("picked item %q, want %q", id, tt.wantID)
			}
			if matches != tt.wantMatches {
				t.Errorf("reported %d matches, want %d", matches, tt.wantMatches)
			}
		})
	}
}

// A duplicate count above 1 is what triggers the operator warning, so it has to be the number of
// items sharing the serial — not the total scanned, and not just "more than one exists".
func TestPickNewestMatchCountsOnlyMatchingItems(t *testing.T) {
	items := []onepassword.ItemOverview{
		overview("a", "SERIAL1", day(1)),
		overview("b", "SERIAL2", day(2)),
		overview("c", "SERIAL1", day(3)),
		overview("d", "SERIAL3", day(4)),
		overview("e", "SERIAL1", day(2)),
	}
	id, matches := pickNewestMatch(items, "SERIAL1")
	if matches != 3 {
		t.Errorf("counted %d duplicates, want 3", matches)
	}
	if id != "c" {
		t.Errorf("picked %q, want the newest matching item \"c\"", id)
	}
}

func TestSetFieldReplacesInPlace(t *testing.T) {
	fields := []onepassword.ItemField{
		{ID: "field_login", Value: "old"},
		{ID: "field_password", Value: "oldpass"},
	}
	fields = setField(fields, onepassword.ItemField{ID: "field_password", Value: "newpass"})

	if len(fields) != 2 {
		t.Fatalf("setField added a duplicate field: %d fields", len(fields))
	}
	for _, f := range fields {
		if f.ID == "field_password" && f.Value != "newpass" {
			t.Errorf("field_password = %q, want %q", f.Value, "newpass")
		}
	}
}

func TestSetFieldAppendsWhenAbsent(t *testing.T) {
	fields := []onepassword.ItemField{{ID: "field_login", Value: "lapsadmin"}}
	fields = setField(fields, onepassword.ItemField{ID: "field_secure_token", Value: "ENABLED"})
	if len(fields) != 2 {
		t.Fatalf("expected the field to be appended, got %d fields", len(fields))
	}
}

// The staged password must be gone once the real password field carries it, otherwise every
// record keeps a second, unmarked copy of a live credential.
func TestRemoveFieldDropsOnlyTheNamedField(t *testing.T) {
	fields := []onepassword.ItemField{
		{ID: "field_login", Value: "lapsadmin"},
		{ID: PendingPasswordFieldID, Value: "staged"},
		{ID: "field_password", Value: "real"},
	}
	fields = removeField(fields, PendingPasswordFieldID)

	if len(fields) != 2 {
		t.Fatalf("expected 2 fields after removal, got %d", len(fields))
	}
	for _, f := range fields {
		if f.ID == PendingPasswordFieldID {
			t.Error("the staged password survived removal")
		}
	}
}

func field(id, value string) onepassword.ItemField {
	return onepassword.ItemField{ID: id, Value: value}
}

func fieldValue(fields []onepassword.ItemField, id string) (string, bool) {
	for _, f := range fields {
		if f.ID == id {
			return f.Value, true
		}
	}
	return "", false
}

func TestApplyRotatedFieldsCommitsPasswordAndDropsPending(t *testing.T) {
	fields := []onepassword.ItemField{
		field("field_password", "old-pass"),
		field(PendingPasswordFieldID, "staged-pass"),
		field("field_hostname", "Old-Name"),
	}
	got := applyRotatedFields(fields, &Credentials{}, "lapsadmin", "new-pass", "ENABLED", "New-Name")

	if v, _ := fieldValue(got, "field_password"); v != "new-pass" {
		t.Fatalf("field_password = %q, want new-pass", v)
	}
	if _, ok := fieldValue(got, PendingPasswordFieldID); ok {
		t.Fatalf("the staged pending field must be removed once the real password field carries it")
	}
	if v, _ := fieldValue(got, "field_hostname"); v != "New-Name" {
		t.Fatalf("field_hostname = %q, want New-Name", v)
	}
	if v, _ := fieldValue(got, "field_secure_token"); v != "ENABLED" {
		t.Fatalf("field_secure_token = %q, want ENABLED", v)
	}
}

func TestApplyRotatedFieldsPreservesLegacyOnlyOnce(t *testing.T) {
	creds := &Credentials{IsMigration: true, OldLogin: "oldadmin", OldPassword: "old-legacy-pass"}
	got := applyRotatedFields(nil, creds, "lapsadmin", "new-pass", "ENABLED", "Host")
	if v, _ := fieldValue(got, "legacy_password_oldadmin"); v != "old-legacy-pass" {
		t.Fatalf("legacy_password_oldadmin = %q, want old-legacy-pass", v)
	}

	// A second rotation must not overwrite the preserved legacy secret with a newer value.
	got = applyRotatedFields(got, &Credentials{IsMigration: true, OldLogin: "oldadmin", OldPassword: "different"}, "lapsadmin", "newer", "ENABLED", "Host")
	if v, _ := fieldValue(got, "legacy_password_oldadmin"); v != "old-legacy-pass" {
		t.Fatalf("legacy_password_oldadmin after second rotation = %q, want old-legacy-pass", v)
	}
}

func TestIsNetworkErrorMatchesObservedFailures(t *testing.T) {
	// Both strings mirror failures observed verbatim in production logs.
	network := fmt.Errorf("listing the LAPS vault failed after 3 attempts: context deadline exceeded (recovered by wazero)")
	if !IsNetworkError(network) {
		t.Fatalf("wazero deadline error must classify as network")
	}
	if !IsNetworkError(fmt.Errorf("wrapped: %w", context.DeadlineExceeded)) {
		t.Fatalf("context.DeadlineExceeded must classify as network")
	}
	conflict := fmt.Errorf("invalid user input: encountered the following errors: The submitted item is not up to date. Refetch the item and retry the request.")
	if IsNetworkError(conflict) {
		t.Fatalf("an item version conflict is a logic condition, not a network failure")
	}
	// Mirrors production failures where the final attempt's error carried these strings and the [NETWORK] marker was missed.
	for _, msg := range []string{
		"listing the LAPS vault failed after 3 attempts: Get \"https://my.1password.com/...\": dial tcp [2600::1]:443: connect: no route to host (recovered by wazero)",
		"read tcp 192.0.2.10:56782->198.51.100.20:443: read: operation timed out (recovered by wazero)",
	} {
		if !IsNetworkError(fmt.Errorf("%s", msg)) {
			t.Fatalf("production-observed network failure not classified as network: %s", msg)
		}
	}
	if IsNetworkError(nil) {
		t.Fatalf("nil must not classify as network")
	}
}
