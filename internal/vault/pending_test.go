// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

package vault

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/1password/onepassword-sdk-go"
)

type fakeItems struct {
	onepassword.ItemsAPI
	items   map[string]onepassword.Item
	order   []string
	nextID  int
	creates int
	puts    int
	createLandsButFails error
}

func newFakeItems() *fakeItems {
	return &fakeItems{items: map[string]onepassword.Item{}}
}

func (f *fakeItems) add(title string, fields ...onepassword.ItemField) string {
	f.nextID++
	id := "item" + strconv.Itoa(f.nextID)
	f.items[id] = onepassword.Item{ID: id, Title: title, VaultID: "vault1", Category: onepassword.ItemCategorySecureNote, Fields: fields}
	f.order = append(f.order, id)
	return id
}

func (f *fakeItems) List(_ context.Context, vaultID string, _ ...onepassword.ItemListFilter) ([]onepassword.ItemOverview, error) {
	var out []onepassword.ItemOverview
	for i, id := range f.order {
		it := f.items[id]
		out = append(out, onepassword.ItemOverview{ID: it.ID, Title: it.Title, VaultID: vaultID, UpdatedAt: day(1).Add(time.Duration(i) * time.Hour)})
	}
	return out, nil
}

func (f *fakeItems) Get(_ context.Context, _ string, itemID string) (onepassword.Item, error) {
	it, ok := f.items[itemID]
	if !ok {
		return onepassword.Item{}, fmt.Errorf("item %s not found", itemID)
	}
	return it, nil
}

func (f *fakeItems) Create(_ context.Context, params onepassword.ItemCreateParams) (onepassword.Item, error) {
	f.creates++
	id := f.add(params.Title, params.Fields...)
	if err := f.createLandsButFails; err != nil {
		f.createLandsButFails = nil
		return onepassword.Item{}, err
	}
	return f.items[id], nil
}

func (f *fakeItems) Put(_ context.Context, item onepassword.Item) (onepassword.Item, error) {
	f.puts++
	if _, ok := f.items[item.ID]; !ok {
		return onepassword.Item{}, fmt.Errorf("item %s not found", item.ID)
	}
	f.items[item.ID] = item
	return item, nil
}

func (f *fakeItems) value(t *testing.T, itemID, fieldID string) (string, bool) {
	t.Helper()
	it, ok := f.items[itemID]
	if !ok {
		t.Fatalf("item %s does not exist", itemID)
	}
	return fieldValue(it.Fields, fieldID)
}

func newTestClient(t *testing.T) (*OPClient, *fakeItems) {
	t.Helper()
	old := retryBackoff
	retryBackoff = func(int) time.Duration { return 0 }
	t.Cleanup(func() { retryBackoff = old })
	f := newFakeItems()
	return &OPClient{items: f}, f
}

func TestStagePendingPasswordKeepsUnconfirmedPending(t *testing.T) {
	op, f := newTestClient(t)
	id := f.add("SERIAL1", field("field_password", "OLD"), field("field_login", "localadmin"), field(PendingPasswordFieldID, "P1"))

	creds, err := op.GetCredentials(context.Background(), "SERIAL1", "vault1", "localadmin")
	if err != nil {
		t.Fatalf("GetCredentials: %v", err)
	}
	if creds.PendingPassword != "P1" {
		t.Fatalf("PendingPassword = %q, want P1", creds.PendingPassword)
	}
	if err := op.StagePendingPassword(context.Background(), creds, "SERIAL1", "host", "vault1", "localadmin", "P2"); err != nil {
		t.Fatalf("StagePendingPassword: %v", err)
	}
	if v, _ := f.value(t, id, PendingPasswordFieldID); v != "P2" {
		t.Fatalf("pending = %q, want P2", v)
	}
	if v, _ := f.value(t, id, PreviousPendingFieldID); v != "P1" {
		t.Fatalf("previous pending = %q, want P1 (the unconfirmed value of run N must survive)", v)
	}

	creds, err = op.GetCredentials(context.Background(), "SERIAL1", "vault1", "localadmin")
	if err != nil {
		t.Fatalf("GetCredentials: %v", err)
	}
	if creds.PendingPassword != "P2" || creds.PreviousPendingPassword != "P1" || creds.OldPassword != "OLD" {
		t.Fatalf("creds = pending %q, previous %q, recorded %q; want P2, P1, OLD", creds.PendingPassword, creds.PreviousPendingPassword, creds.OldPassword)
	}
}

func TestStagePendingPasswordCopiesOnlyADifferentPending(t *testing.T) {
	op, f := newTestClient(t)
	id := f.add("SERIAL1", field("field_password", "OLD"))
	creds := &Credentials{ItemID: id, OldPassword: "OLD"}

	if err := op.StagePendingPassword(context.Background(), creds, "SERIAL1", "host", "vault1", "localadmin", "P1"); err != nil {
		t.Fatalf("StagePendingPassword: %v", err)
	}
	if _, ok := f.value(t, id, PreviousPendingFieldID); ok {
		t.Fatal("no pending value existed, so nothing must be copied into the previous field")
	}

	creds.PendingPassword = "P1"
	if err := op.StagePendingPassword(context.Background(), creds, "SERIAL1", "host", "vault1", "localadmin", "P1"); err != nil {
		t.Fatalf("StagePendingPassword: %v", err)
	}
	if _, ok := f.value(t, id, PreviousPendingFieldID); ok {
		t.Fatal("the same pending value staged again must not be copied into the previous field")
	}
}

func TestApplyRotatedFieldsDropsBothPendingFields(t *testing.T) {
	fields := []onepassword.ItemField{
		field("field_password", "OLD"),
		field(PendingPasswordFieldID, "P2"),
		field(PreviousPendingFieldID, "P1"),
	}
	got := applyRotatedFields(fields, &Credentials{}, "localadmin", "P2", "ENABLED", "host")
	if _, ok := fieldValue(got, PendingPasswordFieldID); ok {
		t.Fatal("the pending field survived the confirming write")
	}
	if _, ok := fieldValue(got, PreviousPendingFieldID); ok {
		t.Fatal("the previous pending field survived the confirming write")
	}
	if v, _ := fieldValue(got, "field_password"); v != "P2" {
		t.Fatalf("field_password = %q, want P2", v)
	}
}

func TestClearPendingPasswordRestoresPreviousPending(t *testing.T) {
	op, f := newTestClient(t)
	id := f.add("SERIAL1", field("field_password", "OLD"), field(PendingPasswordFieldID, "P2"), field(PreviousPendingFieldID, "P1"))

	if err := op.ClearPendingPassword(context.Background(), &Credentials{ItemID: id}, "vault1"); err != nil {
		t.Fatalf("ClearPendingPassword: %v", err)
	}
	if v, _ := f.value(t, id, PendingPasswordFieldID); v != "P1" {
		t.Fatalf("pending after the clear = %q, want P1 restored", v)
	}
	if _, ok := f.value(t, id, PreviousPendingFieldID); ok {
		t.Fatal("the previous pending field must be gone after it moved back")
	}

	if err := op.ClearPendingPassword(context.Background(), &Credentials{ItemID: id}, "vault1"); err != nil {
		t.Fatalf("ClearPendingPassword: %v", err)
	}
	if _, ok := f.value(t, id, PendingPasswordFieldID); ok {
		t.Fatal("the pending field must be removed when no previous value exists")
	}
}

func TestStagePendingPasswordCreateIsIdempotent(t *testing.T) {
	op, f := newTestClient(t)
	f.createLandsButFails = errors.New("context deadline exceeded (recovered by wazero)")
	creds := &Credentials{}

	if err := op.StagePendingPassword(context.Background(), creds, "SERIAL1", "host", "vault1", "localadmin", "P1"); err != nil {
		t.Fatalf("StagePendingPassword: %v", err)
	}
	if f.creates != 1 {
		t.Fatalf("Create called %d time(s), want 1: the retry must adopt the item that landed", f.creates)
	}
	if len(f.items) != 1 {
		t.Fatalf("the vault holds %d items for SERIAL1, want 1", len(f.items))
	}
	if creds.ItemID != "item1" {
		t.Fatalf("creds.ItemID = %q, want the adopted item1", creds.ItemID)
	}
	if f.puts != 1 {
		t.Fatalf("Put called %d time(s) after an adoption, want 1", f.puts)
	}
	if v, _ := f.value(t, "item1", PendingPasswordFieldID); v != "P1" {
		t.Fatalf("pending on the adopted item = %q, want P1", v)
	}
}

func TestStagePendingPasswordCreateNeedsNoSecondWrite(t *testing.T) {
	op, f := newTestClient(t)
	creds := &Credentials{}

	if err := op.StagePendingPassword(context.Background(), creds, "SERIAL1", "host", "vault1", "localadmin", "P1"); err != nil {
		t.Fatalf("StagePendingPassword: %v", err)
	}
	if f.creates != 1 || f.puts != 0 {
		t.Fatalf("creates=%d puts=%d, want one Create and no Put for a fresh item", f.creates, f.puts)
	}
	if creds.ItemID != "item1" {
		t.Fatalf("creds.ItemID = %q, want item1", creds.ItemID)
	}
	if v, _ := f.value(t, "item1", PendingPasswordFieldID); v != "P1" {
		t.Fatalf("pending on the created item = %q, want P1", v)
	}
}

func TestConfirmLivePasswordRecordsTheLiveValue(t *testing.T) {
	op, f := newTestClient(t)
	id := f.add("SERIAL1", field("field_password", "OLD"), field("field_login", "localadmin"), field(PendingPasswordFieldID, "P2"), field(PreviousPendingFieldID, "P1"), field("field_secure_token", "ENABLED (Silent - Vault)"))
	creds := &Credentials{ItemID: id, OldLogin: "localadmin", OldPassword: "OLD", PendingPassword: "P2", PreviousPendingPassword: "P1"}

	if err := op.ConfirmLivePassword(context.Background(), creds, "SERIAL1", "host", "vault1", "localadmin", "P1"); err != nil {
		t.Fatalf("ConfirmLivePassword: %v", err)
	}
	if v, _ := f.value(t, id, "field_password"); v != "P1" {
		t.Fatalf("field_password = %q, want the live value P1", v)
	}
	if _, ok := f.value(t, id, PendingPasswordFieldID); ok {
		t.Fatal("the pending field survived the confirm write")
	}
	if _, ok := f.value(t, id, PreviousPendingFieldID); ok {
		t.Fatal("the previous pending field survived the confirm write")
	}
	if v, _ := f.value(t, id, "field_secure_token"); v != "ENABLED (Silent - Vault)" {
		t.Fatalf("field_secure_token = %q, want it untouched", v)
	}
	if creds.OldPassword != "P1" || creds.PendingPassword != "" || creds.PreviousPendingPassword != "" {
		t.Fatalf("creds = %+v, want OldPassword P1 and both pending values cleared", *creds)
	}
	if f.puts != 1 {
		t.Fatalf("Put called %d time(s), want 1", f.puts)
	}
}

func TestConfirmLivePasswordKeepsLegacyCredentialsOnMigration(t *testing.T) {
	op, f := newTestClient(t)
	id := f.add("SERIAL1", field("field_password", "HEX"), field("field_login", "laps-bridge"), field(PendingPasswordFieldID, "P1"))
	creds := &Credentials{ItemID: id, OldLogin: "laps-bridge", OldPassword: "HEX", PendingPassword: "P1", IsMigration: true}

	if err := op.ConfirmLivePassword(context.Background(), creds, "SERIAL1", "host", "vault1", "localadmin", "P1"); err != nil {
		t.Fatalf("ConfirmLivePassword: %v", err)
	}
	if v, _ := f.value(t, id, "legacy_password_laps-bridge"); v != "HEX" {
		t.Fatalf("legacy_password_laps-bridge = %q, want HEX", v)
	}
	if v, _ := f.value(t, id, "field_login"); v != "localadmin" {
		t.Fatalf("field_login = %q, want localadmin", v)
	}
	if creds.IsMigration || creds.OldLogin != "localadmin" || creds.LegacyLogin != "laps-bridge" || creds.LegacyPassword != "HEX" {
		t.Fatalf("creds = %+v, want the migration recorded as complete", *creds)
	}
}

func TestConfirmLivePasswordRefusesWithoutItem(t *testing.T) {
	op, _ := newTestClient(t)
	if err := op.ConfirmLivePassword(context.Background(), &Credentials{}, "SERIAL1", "host", "vault1", "localadmin", "P1"); err == nil {
		t.Fatal("ConfirmLivePassword must fail without an item")
	}
}

func TestIntegrationVersionFollowsTheSetter(t *testing.T) {
	old := lapsVersion
	t.Cleanup(func() { lapsVersion = old })
	SetIntegrationVersion("1.0.0")
	if got := IntegrationVersion(); got != "v1.0.0" {
		t.Fatalf("integration version = %q, want v1.0.0", got)
	}
}

func TestNewOPClientKeepsTheSDKClientAlive(t *testing.T) {
	c := &onepassword.Client{ItemsAPI: &fakeItems{}}
	op := newOPClient(c)
	if op.client != c {
		t.Fatal("OPClient must hold the *onepassword.Client, or its finalizer releases the client id")
	}
	if op.items == nil {
		t.Fatal("OPClient must also hold the ItemsAPI it calls")
	}
}
