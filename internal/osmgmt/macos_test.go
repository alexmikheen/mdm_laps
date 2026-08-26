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

// The distinction this test protects: "macOS said DISABLED" must be separable from "macOS did not answer". Collapsing the two is what let a timed-out status check delete a healthy admin account, because an empty answer read as "this account has no Secure Token".
func TestParseSecureTokenStatus(t *testing.T) {
	tests := []struct {
		name        string
		output      string
		wantEnabled bool
		wantOK      bool
	}{
		{
			name:        "enabled",
			output:      "2025-01-01 10:00:00 sysadminctl[551:9999] Secure token is ENABLED for user lapsadmin",
			wantEnabled: true, wantOK: true,
		},
		{
			name:        "disabled",
			output:      "2025-01-01 10:00:00 sysadminctl[551:9999] Secure token is DISABLED for user lapsadmin",
			wantEnabled: false, wantOK: true,
		},
		{name: "ON wording", output: "Secure token is ON for user lapsadmin", wantEnabled: true, wantOK: true},
		{name: "OFF wording", output: "Secure token is OFF for user lapsadmin", wantEnabled: false, wantOK: true},
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

// A "DISABLED" substring must never be read as enabled: this account list decides whether laps_token.sh deletes laps-bridge, the last crypto-recovery account on the machine.
func TestParseSecureTokenStatusDoesNotConfuseDisabledWithEnabled(t *testing.T) {
	enabled, ok := parseSecureTokenStatus("Secure token is DISABLED for user lapsadmin")
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
jappleseed                                       501
lapsadmin                                            502
laps-bridge                                           503
root                                             0
daemon                                           1
nobody                                           -2
malformed
weird                                            notanumber
`

	got := parseLocalUsers(dsclOutput)
	want := []string{"jappleseed", "lapsadmin", "laps-bridge"}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseLocalUsers() = %v, want %v", got, want)
	}
}

func TestParseLocalUsersEmpty(t *testing.T) {
	if got := parseLocalUsers(""); len(got) != 0 {
		t.Errorf("parseLocalUsers(\"\") = %v, want no users", got)
	}
}

// The MDM legacy password belongs to a service admin. Offering it to a human account cannot succeed and only fills the log with -14090 noise that reads like a rights problem.
func TestIsServiceAccount(t *testing.T) {
	creds := map[string]string{
		"lapsadmin":         "pw",
		"MDM_FALLBACK_PASS": "legacy",
	}

	tests := []struct {
		name  string
		login string
		want  bool
	}{
		{name: "the target admin itself", login: "lapsadmin", want: true},
		{name: "the legacy service admin", login: "laps-bridge", want: true},
		{name: "an account we hold a vault credential for", login: "MDM_FALLBACK_PASS", want: true},
		{name: "a human account", login: "jappleseed", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isServiceAccount(tt.login, "lapsadmin", creds); got != tt.want {
				t.Errorf("isServiceAccount(%q) = %v, want %v", tt.login, got, tt.want)
			}
		})
	}
}

// Helper output is logged on the success path now, so every secret the payload carried must be scrubbed from it first: the helper's own lines are safe, but sysadminctl writes to the same stderr and OpenDirectory error descriptions are opaque strings.
func TestRedactSecretsMasksEveryPayloadSecret(t *testing.T) {
	p := SwiftPayload{
		Action:     "change_password",
		TargetUser: "lapsadmin",
		TargetPass: "NewPass-123",
		OldPass:    "LegacyPass-456",
		AdminPass:  "AdminPass-789",
	}

	in := "[SWIFT] error: NewPass-123 LegacyPass-456 AdminPass-789 for lapsadmin"
	got := redactSecrets(in, p.secrets())

	for _, secret := range []string{"NewPass-123", "LegacyPass-456", "AdminPass-789"} {
		if strings.Contains(got, secret) {
			t.Errorf("redacted output still contains secret %q: %s", secret, got)
		}
	}
	if !strings.Contains(got, "lapsadmin") {
		t.Errorf("redaction must keep non-secret content (account name): %s", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Errorf("expected [REDACTED] markers in output: %s", got)
	}
}

// An empty secret must never reach strings.ReplaceAll — replacing "" inserts the marker between every character of the output. Payloads legitimately carry empty fields (verify_password has no OldPass or AdminPass), so secrets() has to drop them.
func TestSecretsSkipsEmptyFields(t *testing.T) {
	p := SwiftPayload{Action: "verify_password", TargetUser: "jappleseed", TargetPass: "OnlyOne"}

	got := p.secrets()
	if !reflect.DeepEqual(got, []string{"OnlyOne"}) {
		t.Errorf("secrets() = %v, want [OnlyOne]", got)
	}

	if out := redactSecrets("[SWIFT] User jappleseed not found", p.secrets()); strings.Contains(out, "[REDACTED][REDACTED]") {
		t.Errorf("empty-string secret corrupted the output: %s", out)
	}
}

// The helper's exit codes ARE the contract between the two languages: Go reads them to decide whether to escalate a token holder to recreation. Nothing at build time links the Swift enum to the Go constants, so reordering the Swift cases would silently turn "locked" into "auth-failed" — or worse, "ok". This test parses the helper and asserts the numbers still line up.
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

func TestChangeOutcomeString(t *testing.T) {
	// The label reaches the MDM log and is how an operator tells "the password is wrong" apart from "opendirectoryd refused the reset" — two states that used to look identical.
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
