// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

//go:build darwin

package osmgmt

import (
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestParseSecureTokenStatus(t *testing.T) {
	tests := []struct {
		name        string
		output      string
		wantEnabled bool
		wantOK      bool
	}{
		{
			name:        "enabled",
			output:      "2026-08-11 10:00:00 sysadminctl[551:9999] Secure token is ENABLED for user localadmin",
			wantEnabled: true, wantOK: true,
		},
		{
			name:        "disabled",
			output:      "2026-08-11 10:00:00 sysadminctl[551:9999] Secure token is DISABLED for user localadmin",
			wantEnabled: false, wantOK: true,
		},
		{name: "ON wording", output: "Secure token is ON for user localadmin", wantEnabled: true, wantOK: true},
		{name: "OFF wording", output: "Secure token is OFF for user localadmin", wantEnabled: false, wantOK: true},
		{name: "empty output is not an answer", output: "", wantEnabled: false, wantOK: false},
		{
			name:        "unrelated error is not an answer",
			output:      "sysadminctl[551:9999] Unable to find user record",
			wantEnabled: false, wantOK: false,
		},
		{
			name:        "the word ENABLED alone is not an answer",
			output:      "some line mentioning ENABLED without the phrase",
			wantEnabled: false, wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enabled, ok := parseSecureTokenStatus(tt.output)
			if enabled != tt.wantEnabled || ok != tt.wantOK {
				t.Errorf("parseSecureTokenStatus(%q) = (%v, %v), want (%v, %v)", tt.output, enabled, ok, tt.wantEnabled, tt.wantOK)
			}
		})
	}
}

func TestParseSecureTokenStatusDoesNotConfuseDisabledWithEnabled(t *testing.T) {
	enabled, ok := parseSecureTokenStatus("Secure token is DISABLED for user localadmin")
	if !ok {
		t.Fatal("DISABLED should be a definite answer")
	}
	if enabled {
		t.Fatal("DISABLED was read as enabled")
	}
}

func TestParseLocalUsers(t *testing.T) {
	const dsclOutput = `_amavisd                                         83
_appleevents                                     55
jdoe                                       501
localadmin                                            502
laps-bridge                                           503
root                                             0
daemon                                           1
nobody                                           -2
malformed
weird                                            notanumber
`

	got := parseLocalUsers(dsclOutput)
	want := []string{"jdoe", "localadmin", "laps-bridge"}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseLocalUsers() = %v, want %v", got, want)
	}
}

func TestParseLocalUsersEmpty(t *testing.T) {
	if got := parseLocalUsers(""); len(got) != 0 {
		t.Errorf("parseLocalUsers(\"\") = %v, want no users", got)
	}
}

func TestIsServiceAccount(t *testing.T) {
	creds := map[string]string{
		"localadmin":             "pw",
		"MDM_FALLBACK_PASS": "legacy",
	}

	tests := []struct {
		name  string
		login string
		want  bool
	}{
		{name: "the target admin itself", login: "localadmin", want: true},
		{name: "the legacy service admin", login: "laps-bridge", want: true},
		{name: "an account we hold a vault credential for", login: "MDM_FALLBACK_PASS", want: true},
		{name: "a human account", login: "jdoe", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isServiceAccount(tt.login, "localadmin", creds); got != tt.want {
				t.Errorf("isServiceAccount(%q) = %v, want %v", tt.login, got, tt.want)
			}
		})
	}
}

func TestRedactSecretsMasksEveryPayloadSecret(t *testing.T) {
	p := SwiftPayload{
		Action:     "change_password",
		TargetUser: "localadmin",
		TargetPass: "NewPass-123",
		OldPass:    "LegacyPass-456",
		AdminPass:  "AdminPass-789",
	}

	in := "[SWIFT] error: NewPass-123 LegacyPass-456 AdminPass-789 for localadmin"
	got := redactSecrets(in, p.secrets())

	for _, secret := range []string{"NewPass-123", "LegacyPass-456", "AdminPass-789"} {
		if strings.Contains(got, secret) {
			t.Errorf("redacted output still contains secret %q: %s", secret, got)
		}
	}
	if !strings.Contains(got, "localadmin") {
		t.Errorf("redaction must keep non-secret content (account name): %s", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Errorf("expected [REDACTED] markers in output: %s", got)
	}
}

func TestSecretsSkipsEmptyFields(t *testing.T) {
	p := SwiftPayload{Action: "verify_password", TargetUser: "jdoe", TargetPass: "OnlyOne"}

	got := p.secrets()
	if !reflect.DeepEqual(got, []string{"OnlyOne"}) {
		t.Errorf("secrets() = %v, want [OnlyOne]", got)
	}

	if out := redactSecrets("[SWIFT] User jdoe not found", p.secrets()); strings.Contains(out, "[REDACTED][REDACTED]") {
		t.Errorf("empty-string secret corrupted the output: %s", out)
	}
}

func TestChangeOutcomeValuesMatchSwiftHelper(t *testing.T) {
	src, err := os.ReadFile("mac_helper.swift")
	if err != nil {
		t.Fatalf("cannot read the Swift helper: %v", err)
	}

	want := map[string]changeOutcome{
		"ok":             changeOK,
		"odError":        changeODError,
		"authFailed":     changeAuthFailed,
		"locked":         changeLocked,
		"resetRefused":   changeResetRefused,
		"policyRejected": changePolicyRejected,
	}

	re := regexp.MustCompile(`case\s+(ok|odError|authFailed|locked|resetRefused|policyRejected)\s*=\s*(\d+)`)
	matches := re.FindAllStringSubmatch(string(src), -1)
	if len(matches) != len(want) {
		t.Fatalf("found %d ChangeOutcome cases in mac_helper.swift, want %d — did the enum change shape?", len(matches), len(want))
	}

	for _, m := range matches {
		name, raw := m[1], m[2]
		got, err := strconv.Atoi(raw)
		if err != nil {
			t.Fatalf("case %s has a non-numeric raw value %q", name, raw)
		}
		if changeOutcome(got) != want[name] {
			t.Errorf("Swift case %s = %d, but Go has %s = %d", name, got, name, want[name])
		}
	}
}

func TestSwiftProgramsIgnoreSIGPIPE(t *testing.T) {
	for _, file := range []string{"mac_helper.swift", "auth_window.swift"} {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("cannot read %s: %v", file, err)
		}
		if !regexp.MustCompile(`(?m)^signal\(SIGPIPE, SIG_IGN\)`).Match(src) {
			t.Errorf("%s lost the top-level signal(SIGPIPE, SIG_IGN) call", file)
		}
	}
}

func TestChangeOutcomeString(t *testing.T) {
	for outcome, want := range map[changeOutcome]string{
		changeOK:           "ok",
		changeODError:      "od-error",
		changeAuthFailed:   "auth-failed",
		changeLocked:       "locked",
		changeResetRefused: "reset-refused",
		changeOutcome(99):  "unknown(99)",
	} {
		if got := outcome.String(); got != want {
			t.Errorf("changeOutcome(%d).String() = %q, want %q", int(outcome), got, want)
		}
	}
}

func TestParseMacSerialRejectsPlaceholders(t *testing.T) {
	for _, bad := range []string{
		"",
		`"IOPlatformUUID" = "ABC"`,
		`"IOPlatformSerialNumber" = ""`,
		`"IOPlatformSerialNumber" = "Unknown"`,
		`"IOPlatformSerialNumber" = "unknown"`,
		`"IOPlatformSerialNumber" = "   "`,
		`"IOPlatformSerialNumber" = "abc123"`,
		`"IOPlatformSerialNumber" = "D3936T0L7X extra"`,
		`"IOPlatformSerialNumber" = "ABCDEFGHIJKLMNOPQRSTU"`,
	} {
		if got, err := parseMacSerial(bad); err == nil {
			t.Fatalf("parseMacSerial(%q) = %q, want an error", bad, got)
		}
	}
	for _, good := range []string{"D3936T0L7X", "C02TEST00001", "C02ZW1ABMD6T", "C02TEST00002"} {
		out := "    |   \"IOPlatformSerialNumber\" = \"" + good + "\"\n"
		got, err := parseMacSerial(out)
		if err != nil {
			t.Fatalf("parseMacSerial for %s: %v", good, err)
		}
		if got != good {
			t.Fatalf("parseMacSerial = %q, want %q", got, good)
		}
	}
}
