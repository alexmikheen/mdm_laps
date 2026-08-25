//go:build darwin

package osmgmt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// These tests exist because the heal/bridge/dscl ladder shipped to production untested: the
// last-admin bridge and the dscl build have never fired on the fleet (no machine was left in the
// right state), so a scripted runner is the only way to prove those branches before they matter.

// fakeExit mimics an *exec.ExitError through the exitCode() interface, so a scripted non-zero
// exit takes the same path in the code under test as a real process failure.
type fakeExit struct{ code int }

func (e fakeExit) Error() string { return fmt.Sprintf("exit status %d", e.code) }
func (e fakeExit) ExitCode() int { return e.code }

type call struct {
	stdin string
	name  string
	args  []string
}

func (c call) String() string { return strings.TrimSpace(c.name + " " + strings.Join(c.args, " ")) }

func (c call) is(name string, args ...string) bool {
	if c.name != name || len(c.args) != len(args) {
		return false
	}
	for i := range args {
		if c.args[i] != args[i] {
			return false
		}
	}
	return true
}

type fakeRunner struct {
	handle func(c call) ([]byte, error)
	calls  []call
}

func (f *fakeRunner) Run(_ context.Context, stdin, name string, args ...string) ([]byte, error) {
	c := call{stdin: stdin, name: name, args: args}
	f.calls = append(f.calls, c)
	return f.handle(c)
}

// indexOf returns the position of the first call matching pattern (rendered via call.String), or -1.
func (f *fakeRunner) indexOf(pattern string) int {
	for i, c := range f.calls {
		if strings.Contains(c.String(), pattern) {
			return i
		}
	}
	return -1
}

func (f *fakeRunner) count(pattern string) int {
	n := 0
	for _, c := range f.calls {
		if strings.Contains(c.String(), pattern) {
			n++
		}
	}
	return n
}

func newTestManager(f *fakeRunner) *MacOSManager {
	// The GUI prompt is stubbed to "user did not comply" — the real one drives osascript at the console.
	return &MacOSManager{run: f, sleep: func(time.Duration) {}, prompt: func(context.Context, string, string) bool { return false }}
}

// fakeOS is the little state machine the scripted runner consults: which accounts exist and which
// hold a token. Handlers mutate it the way the real commands would.
type fakeOS struct {
	exists map[string]bool
	token  map[string]bool
}

func (o *fakeOS) handleCommon(c call) ([]byte, error, bool) {
	switch {
	case c.name == "id" && len(c.args) == 2 && c.args[0] == "-u":
		user := c.args[1]
		if o.exists[user] {
			return []byte("501"), nil, true
		}
		return []byte("id: " + user + ": no such user"), fakeExit{1}, true
	case c.name == "sysadminctl" && len(c.args) == 2 && c.args[0] == "-secureTokenStatus":
		user := c.args[1]
		if o.token[user] {
			return []byte("Secure token is ENABLED for user " + user), nil, true
		}
		return []byte("Secure token is DISABLED for user " + user), nil, true
	case c.name == "dscl" && c.args[len(c.args)-1] == "1": // dscl . create /Users/x IsHidden 1
		return nil, nil, true
	case c.name == "odutil":
		return nil, nil, true
	}
	return nil, nil, false
}

// TestHealAccountBridgesLastAdminGuard drives the full ladder: the target is the last admin, so
// the first delete is refused; a bridge admin makes it deletable; the target is recreated INSIDE
// the bridge window; the token-less bridge is removed afterwards.
func TestHealAccountBridgesLastAdminGuard(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{"lapsadmin": true}, token: map[string]bool{}}

	f := &fakeRunner{}
	f.handle = func(c call) ([]byte, error) {
		if out, err, ok := osState.handleCommon(c); ok {
			return out, err
		}
		switch {
		case c.is("sysadminctl", "-deleteUser", "lapsadmin"):
			if !osState.exists["laps-bridge"] {
				return []byte("Unable to delete the last admin user"), fakeExit{1}
			}
			delete(osState.exists, "lapsadmin")
			return nil, nil
		case c.is("sysadminctl", "-deleteUser", "laps-bridge"):
			delete(osState.exists, "laps-bridge")
			return nil, nil
		case c.name == "sysadminctl" && c.args[0] == "-addUser":
			osState.exists[c.args[1]] = true
			return nil, nil
		}
		t.Fatalf("unexpected command: %s", c)
		return nil, nil
	}

	m := newTestManager(f)
	if err := m.healAccount(context.Background(), "lapsadmin", "NewPass-1"); err != nil {
		t.Fatalf("healAccount failed: %v", err)
	}

	bridgeCreated := f.indexOf("sysadminctl -addUser laps-bridge")
	targetRecreated := f.indexOf("sysadminctl -addUser lapsadmin")
	bridgeDeleted := f.indexOf("sysadminctl -deleteUser laps-bridge")
	if bridgeCreated < 0 || targetRecreated < 0 || bridgeDeleted < 0 {
		t.Fatalf("missing ladder steps in call sequence: %v", f.calls)
	}
	if !(bridgeCreated < targetRecreated && targetRecreated < bridgeDeleted) {
		t.Fatalf("ladder out of order (bridge %d, recreate %d, cleanup %d): the target must be recreated inside the bridge window", bridgeCreated, targetRecreated, bridgeDeleted)
	}
	if !osState.exists["lapsadmin"] || osState.exists["laps-bridge"] {
		t.Fatalf("end state wrong: exists=%v", osState.exists)
	}
}

// The bridge reuses an existing laps-bridge instead of creating a second one.
func TestWithBridgeAdminReusesExistingBridge(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{"lapsadmin": true, "laps-bridge": true}, token: map[string]bool{}}

	f := &fakeRunner{}
	deleteAttempts := 0
	f.handle = func(c call) ([]byte, error) {
		if out, err, ok := osState.handleCommon(c); ok {
			return out, err
		}
		switch {
		case c.is("sysadminctl", "-deleteUser", "lapsadmin"):
			deleteAttempts++
			if deleteAttempts == 1 {
				return []byte("refused"), fakeExit{1}
			}
			delete(osState.exists, "lapsadmin")
			return nil, nil
		case c.is("sysadminctl", "-deleteUser", "laps-bridge"):
			delete(osState.exists, "laps-bridge")
			return nil, nil
		case c.name == "sysadminctl" && c.args[0] == "-addUser":
			osState.exists[c.args[1]] = true
			return nil, nil
		}
		t.Fatalf("unexpected command: %s", c)
		return nil, nil
	}

	m := newTestManager(f)
	if err := m.healAccount(context.Background(), "lapsadmin", "NewPass-1"); err != nil {
		t.Fatalf("healAccount failed: %v", err)
	}
	if n := f.count("sysadminctl -addUser laps-bridge"); n != 0 {
		t.Fatalf("laps-bridge already existed but was created %d time(s)", n)
	}
}

// A bridge that HOLDS a Secure Token may be the device's only token holder — cleanup must keep it.
func TestWithBridgeAdminKeepsTokenHoldingBridge(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{"lapsadmin": true, "laps-bridge": true}, token: map[string]bool{"laps-bridge": true}}

	f := &fakeRunner{}
	f.handle = func(c call) ([]byte, error) {
		if out, err, ok := osState.handleCommon(c); ok {
			return out, err
		}
		t.Fatalf("unexpected command: %s", c)
		return nil, nil
	}

	m := newTestManager(f)
	err := m.withBridgeAdmin(context.Background(), "lapsadmin", func() error { return nil })
	if err != nil {
		t.Fatalf("withBridgeAdmin failed: %v", err)
	}
	if f.count("sysadminctl -deleteUser laps-bridge") != 0 {
		t.Fatal("a token-holding bridge was deleted — it may have been the device's only token holder")
	}
}

// If fn left the target missing, deleting the bridge would remove the device's only admin.
func TestWithBridgeAdminKeepsBridgeWhenTargetMissing(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{"laps-bridge": true}, token: map[string]bool{}}

	f := &fakeRunner{}
	f.handle = func(c call) ([]byte, error) {
		if out, err, ok := osState.handleCommon(c); ok {
			return out, err
		}
		t.Fatalf("unexpected command: %s", c)
		return nil, nil
	}

	m := newTestManager(f)
	fnErr := fmt.Errorf("recreate failed")
	if err := m.withBridgeAdmin(context.Background(), "lapsadmin", func() error { return fnErr }); err != fnErr {
		t.Fatalf("withBridgeAdmin must surface fn's error, got: %v", err)
	}
	if f.count("sysadminctl -deleteUser laps-bridge") != 0 {
		t.Fatal("bridge deleted while the target is missing — the device would be left with no admin")
	}
}

// decodePayload extracts the SwiftPayload a scripted mac_helper call received on stdin.
func decodePayload(t *testing.T, c call) SwiftPayload {
	t.Helper()
	var p SwiftPayload
	if err := json.Unmarshal([]byte(c.stdin), &p); err != nil {
		t.Fatalf("mac_helper stdin is not a SwiftPayload: %v | %q", err, c.stdin)
	}
	return p
}

// TestCreateHiddenAdminPhantomRecovery: sysadminctl exits 0 without creating, twice — the account
// is finally assembled via dscl, sealed with a throwaway password and rotated to the real one over
// stdin with the administrative reset permitted (the one legitimately token-less case).
func TestCreateHiddenAdminPhantomRecovery(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{}, token: map[string]bool{}}
	const realPass = "Real-Pass-123"

	f := &fakeRunner{}
	var helperPayload *SwiftPayload
	f.handle = func(c call) ([]byte, error) {
		if out, err, ok := osState.handleCommon(c); ok {
			return out, err
		}
		switch {
		case c.name == "sysadminctl" && c.args[0] == "-addUser":
			return nil, nil // exit 0, account NOT created — the phantom
		case c.is("dscl", ".", "-list", "/Users", "UniqueID"):
			return []byte("root 0\nlapsadminmin 501\n"), nil
		case c.name == "dscl" && (c.args[1] == "-create" || c.args[1] == "-passwd"):
			return nil, nil
		case c.name == "dscl" && c.args[1] == "-list":
			return []byte(""), nil
		case c.name == "dseditgroup":
			osState.exists["lapsadmin"] = true // the dscl build is what finally lands the record
			return nil, nil
		case c.name == "/usr/local/bin/mac_helper":
			p := decodePayload(t, c)
			helperPayload = &p
			return []byte("[SWIFT] Password natively changed"), nil
		}
		t.Fatalf("unexpected command: %s", c)
		return nil, nil
	}

	m := newTestManager(f)
	if err := m.createHiddenAdmin(context.Background(), "lapsadmin", "IT Admin", realPass); err != nil {
		t.Fatalf("createHiddenAdmin failed: %v", err)
	}

	if n := f.count("sysadminctl -addUser lapsadmin"); n != 2 {
		t.Fatalf("expected exactly 2 sysadminctl -addUser attempts around the OD cache reset, got %d", n)
	}
	if f.indexOf("odutil reset cache") < 0 {
		t.Fatal("the OD cache reset between the two addUser attempts never happened")
	}
	if helperPayload == nil {
		t.Fatal("the dscl build never rotated the throwaway password through the helper")
	}
	if helperPayload.TargetPass != realPass || helperPayload.OldPass == "" || !helperPayload.AllowAdminReset {
		t.Fatalf("throwaway rotation payload wrong: target=%q old set=%v allowAdminReset=%v", helperPayload.TargetPass, helperPayload.OldPass != "", helperPayload.AllowAdminReset)
	}
	// The real password must never appear in a dscl argument list — only the throwaway may.
	for _, c := range f.calls {
		if c.name == "dscl" {
			for _, a := range c.args {
				if a == realPass {
					t.Fatalf("real password leaked into dscl argv: %s", c)
				}
			}
		}
	}
}

// The class that poisoned the vault: a token holder whose recorded password no longer works. The
// helper reports auth-failed/locked and Go must escalate to recreation — never retry the helper
// with an administrative reset, never report success without recreating.
func TestEnsureUserEscalatesFailedRotationToRecreation(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
	}{
		{name: "auth-failed", code: 2},
		{name: "locked", code: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			osState := &fakeOS{exists: map[string]bool{"lapsadmin": true}, token: map[string]bool{"lapsadmin": true}}

			f := &fakeRunner{}
			f.handle = func(c call) ([]byte, error) {
				if out, err, ok := osState.handleCommon(c); ok {
					return out, err
				}
				switch {
				case c.is("pwpolicy", "-u", "lapsadmin", "authentication-allowed"):
					return []byte("Password authentication is allowed"), nil
				case c.name == "/usr/local/bin/mac_helper":
					p := decodePayload(t, c)
					if p.AllowAdminReset {
						t.Fatal("AllowAdminReset must stay false for a token holder")
					}
					return []byte("[SWIFT] Authenticated change failed"), fakeExit{tc.code}
				case c.is("sysadminctl", "-deleteUser", "lapsadmin"):
					delete(osState.exists, "lapsadmin")
					return nil, nil
				case c.name == "sysadminctl" && c.args[0] == "-addUser":
					osState.exists[c.args[1]] = true
					return nil, nil
				}
				t.Fatalf("unexpected command: %s", c)
				return nil, nil
			}

			m := newTestManager(f)
			if err := m.EnsureUserAndChangePassword(context.Background(), "lapsadmin", "old-pass", "", "new-pass"); err != nil {
				t.Fatalf("expected escalation to recreation to succeed, got: %v", err)
			}
			if f.count("/usr/local/bin/mac_helper") != 1 {
				t.Fatal("the helper must be called exactly once — a second call would be the forbidden administrative-reset retry")
			}
			if f.indexOf("sysadminctl -deleteUser lapsadmin") < 0 || f.indexOf("sysadminctl -addUser lapsadmin") < 0 {
				t.Fatalf("escalation to recreation never happened: %v", f.calls)
			}
		})
	}
}

// reset-refused (and any other non-ok outcome that is not auth-failed/locked) must surface as an
// error — success here is exactly the phantom PASS that escrowed passwords the device never took.
func TestEnsureUserReportsResetRefusedAsError(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{"lapsadmin": true}, token: map[string]bool{"lapsadmin": true}}

	f := &fakeRunner{}
	f.handle = func(c call) ([]byte, error) {
		if out, err, ok := osState.handleCommon(c); ok {
			return out, err
		}
		switch {
		case c.is("pwpolicy", "-u", "lapsadmin", "authentication-allowed"):
			return []byte("Password authentication is allowed"), nil
		case c.name == "/usr/local/bin/mac_helper":
			return []byte("[SWIFT] Administrative reset was REFUSED"), fakeExit{4}
		}
		t.Fatalf("unexpected command: %s", c)
		return nil, nil
	}

	m := newTestManager(f)
	err := m.EnsureUserAndChangePassword(context.Background(), "lapsadmin", "old-pass", "", "new-pass")
	if err == nil || !strings.Contains(err.Error(), "reset-refused") {
		t.Fatalf("a refused reset must fail the run with the outcome named, got: %v", err)
	}
	if f.count("sysadminctl -deleteUser lapsadmin") != 0 {
		t.Fatal("reset-refused must not trigger recreation on its own")
	}
}

// The pwpolicy gate: a token holder that pwpolicy says cannot authenticate goes straight to
// recreation without ever calling the helper (laps_token.sh already ran the soft repairs).
func TestEnsureUserRecreatesWhenPwpolicyBlocksAuthentication(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{"lapsadmin": true}, token: map[string]bool{"lapsadmin": true}}

	f := &fakeRunner{}
	f.handle = func(c call) ([]byte, error) {
		if out, err, ok := osState.handleCommon(c); ok {
			return out, err
		}
		switch {
		case c.is("pwpolicy", "-u", "lapsadmin", "authentication-allowed"):
			return []byte("User lapsadmin is not allowed to authenticate until password is changed"), nil
		case c.is("sysadminctl", "-deleteUser", "lapsadmin"):
			delete(osState.exists, "lapsadmin")
			return nil, nil
		case c.name == "sysadminctl" && c.args[0] == "-addUser":
			osState.exists[c.args[1]] = true
			return nil, nil
		}
		t.Fatalf("unexpected command: %s", c)
		return nil, nil
	}

	m := newTestManager(f)
	if err := m.EnsureUserAndChangePassword(context.Background(), "lapsadmin", "old-pass", "", "new-pass"); err != nil {
		t.Fatalf("recreation after a pwpolicy block failed: %v", err)
	}
	if f.count("/usr/local/bin/mac_helper") != 0 {
		t.Fatal("the helper must not be asked to rotate an account pwpolicy already declared blocked")
	}
}

// btCoveredHandler scripts a device where lapsadmin has no token, no other holder exists, and MDM recovery is fully covered.
func btCoveredHandler(o *fakeOS, prkOut string, prkErr error, profilesOut string, profilesErr error) func(call) ([]byte, error) {
	return func(c call) ([]byte, error) {
		if out, err, done := o.handleCommon(c); done {
			return out, err
		}
		switch {
		case c.is("dscl", ".", "-list", "/Users", "UniqueID"):
			return []byte(""), nil
		case c.is("fdesetup", "haspersonalrecoverykey"):
			return []byte(prkOut), prkErr
		case c.is("profiles", "status", "-type", "bootstraptoken"):
			return []byte(profilesOut), profilesErr
		}
		return nil, fmt.Errorf("unexpected call: %s", c)
	}
}

const profilesEscrowedYES = "profiles: Bootstrap Token supported on server: YES\nprofiles: Bootstrap Token escrowed to server: YES"

func TestManageSecureTokenReportsCoveredOnlyAfterPromptFails(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{"lapsadmin": true}, token: map[string]bool{}}
	f := &fakeRunner{}
	f.handle = btCoveredHandler(osState, "true", nil, profilesEscrowedYES, nil)
	m := newTestManager(f)
	prompted := false
	m.prompt = func(context.Context, string, string) bool { prompted = true; return false }

	status := m.ManageSecureToken(context.Background(), "lapsadmin", "newpass", map[string]string{})
	if status != TokenStatusDisabledCovered {
		t.Fatalf("status = %q, want %q", status, TokenStatusDisabledCovered)
	}
	// Coverage softens the report; it must never replace the restoration attempt — a tokenless admin is not an accepted end state.
	if !prompted {
		t.Fatal("the GUI prompt was skipped: coverage must not cancel token restoration")
	}
	if f.count("fdesetup haspersonalrecoverykey") != 1 || f.count("profiles status -type bootstraptoken") != 1 {
		t.Fatalf("coverage checks not performed exactly once: %v", f.calls)
	}
}

func TestManageSecureTokenPromptSuccessNeedsNoCoverageCheck(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{"lapsadmin": true}, token: map[string]bool{}}
	f := &fakeRunner{}
	f.handle = btCoveredHandler(osState, "true", nil, profilesEscrowedYES, nil)
	m := newTestManager(f)
	m.prompt = func(context.Context, string, string) bool { return true }

	if status := m.ManageSecureToken(context.Background(), "lapsadmin", "newpass", map[string]string{}); status != "ENABLED (Via GUI Prompt)" {
		t.Fatalf("status = %q, want the GUI-grant success", status)
	}
	if f.count("fdesetup") != 0 {
		t.Fatalf("coverage was consulted although the token was granted: %v", f.calls)
	}
}

func TestRecoveryCoverageFailsClosed(t *testing.T) {
	tests := []struct {
		name        string
		prkOut      string
		prkErr      error
		profilesOut string
		profilesErr error
	}{
		{name: "no PRK", prkOut: "false"},
		{name: "fdesetup error", prkOut: "", prkErr: fakeExit{1}},
		{name: "BT not escrowed", prkOut: "true", profilesOut: "profiles: Bootstrap Token supported on server: YES\nprofiles: Bootstrap Token escrowed to server: NO"},
		{name: "profiles error", prkOut: "true", profilesOut: "", profilesErr: fakeExit{1}},
		{name: "unrecognised profiles output", prkOut: "true", profilesOut: "profiles: something new entirely"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeRunner{}
			f.handle = func(c call) ([]byte, error) {
				switch {
				case c.is("fdesetup", "haspersonalrecoverykey"):
					return []byte(tt.prkOut), tt.prkErr
				case c.is("profiles", "status", "-type", "bootstraptoken"):
					return []byte(tt.profilesOut), tt.profilesErr
				}
				return nil, fmt.Errorf("unexpected call: %s", c)
			}
			if newTestManager(f).recoveryCoveredByMDM(context.Background()) {
				t.Fatalf("recovery must read as NOT covered")
			}
		})
	}
}

func TestManageSecureTokenUncoveredStaysRed(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{"lapsadmin": true}, token: map[string]bool{}}
	f := &fakeRunner{}
	f.handle = btCoveredHandler(osState, "false", nil, "profiles: something unhelpful", nil)
	m := newTestManager(f)

	// prompt is stubbed to false by newTestManager; with no coverage the run must stay an honest failure.
	if status := m.ManageSecureToken(context.Background(), "lapsadmin", "newpass", map[string]string{}); status != "DISABLED (Review Required)" {
		t.Fatalf("status = %q, want the red Review Required status on an uncovered device", status)
	}
}

func TestEnsureUserPolicyRejectedDoesNotRecreate(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{"lapsadmin": true}, token: map[string]bool{"lapsadmin": true}}
	f := &fakeRunner{}
	f.handle = func(c call) ([]byte, error) {
		if out, err, ok := osState.handleCommon(c); ok {
			return out, err
		}
		switch {
		case c.is("pwpolicy", "-u", "lapsadmin", "authentication-allowed"):
			return []byte("Password authentication is allowed"), nil
		case c.name == "/usr/local/bin/mac_helper":
			return []byte("[SWIFT] policy rejected the new password"), fakeExit{5}
		}
		t.Fatalf("unexpected command: %s", c)
		return nil, nil
	}

	m := newTestManager(f)
	err := m.EnsureUserAndChangePassword(context.Background(), "lapsadmin", "old-pass", "", "new-pass")
	if !errors.Is(err, ErrPolicyRejected) {
		t.Fatalf("want ErrPolicyRejected, got: %v", err)
	}
	// The account is healthy — a rejected NEW password must never trigger the recreation ladder.
	if f.count("sysadminctl -deleteUser") != 0 {
		t.Fatalf("a policy-rejected rotation recreated a healthy admin: %v", f.calls)
	}
}

func TestEnsureUserTriesStagedPasswordBeforeRecreation(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{"lapsadmin": true}, token: map[string]bool{"lapsadmin": true}}
	f := &fakeRunner{}
	var oldPasses []string
	f.handle = func(c call) ([]byte, error) {
		if out, err, ok := osState.handleCommon(c); ok {
			return out, err
		}
		switch {
		case c.is("pwpolicy", "-u", "lapsadmin", "authentication-allowed"):
			return []byte("Password authentication is allowed"), nil
		case c.name == "/usr/local/bin/mac_helper":
			p := decodePayload(t, c)
			oldPasses = append(oldPasses, p.OldPass)
			if p.OldPass == "staged-live" {
				return []byte("[SWIFT] Password natively changed"), nil
			}
			return []byte("[SWIFT] Authenticated change failed"), fakeExit{2}
		}
		t.Fatalf("unexpected command: %s", c)
		return nil, nil
	}

	m := newTestManager(f)
	if err := m.EnsureUserAndChangePassword(context.Background(), "lapsadmin", "stale-recorded", "staged-live", "new-pass"); err != nil {
		t.Fatalf("the staged fallback should have completed the rotation: %v", err)
	}
	if len(oldPasses) != 2 || oldPasses[0] != "stale-recorded" || oldPasses[1] != "staged-live" {
		t.Fatalf("expected recorded-then-staged attempts, got %v", oldPasses)
	}
	// The whole point: a live staged password must never cost the account (and its token) a recreation.
	if f.count("sysadminctl -deleteUser") != 0 {
		t.Fatalf("recreation happened despite the staged password working: %v", f.calls)
	}
}
