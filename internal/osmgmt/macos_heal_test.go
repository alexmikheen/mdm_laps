// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

//go:build darwin

package osmgmt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeExit struct{ code int }

func (e fakeExit) Error() string { return fmt.Sprintf("exit status %d", e.code) }
func (e fakeExit) ExitCode() int { return e.code }

type call struct {
	stdin string
	path string
	name string
	args []string
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
	bare []string
}

func (f *fakeRunner) Run(_ context.Context, stdin, name string, args ...string) ([]byte, error) {
	c := call{stdin: stdin, path: name, name: filepath.Base(name), args: args}
	if !filepath.IsAbs(name) {
		f.bare = append(f.bare, c.String())
	}
	f.calls = append(f.calls, c)
	return f.handle(c)
}

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

func newTestManager(t *testing.T, f *fakeRunner) *MacOSManager {
	t.Helper()
	t.Cleanup(func() {
		if len(f.bare) > 0 {
			t.Errorf("the code called a tool by a bare name, which PATH resolves: %v", f.bare)
		}
	})
	return &MacOSManager{
		run:           f,
		sleep:         func(time.Duration) {},
		prompt:        func(context.Context, string, string) promptResult { return promptResult{outcome: passwordUnavailable} },
		probe:         func(context.Context, string) error { return nil },
		now:           time.Now,
		healStatePath: filepath.Join(t.TempDir(), "last_heal"),
		escrowBridge: func(context.Context, string) error { return nil },
		lstat: rootOwnedLstat,
	}
}

type fakeOS struct {
	exists   map[string]bool
	token    map[string]bool
	realName map[string]string
	failed   map[string]int
	blocked  map[string]bool
	hidden   map[string]bool
}

func (o *fakeOS) cryptoUsers() string {
	var b strings.Builder
	n := 2
	for _, has := range o.token {
		if has {
			n++
		}
	}
	fmt.Fprintf(&b, "Cryptographic users for disk3s1 (%d found)\n|\n", n)
	for user, has := range o.token {
		if has {
			fmt.Fprintf(&b, "+-- 0000-%s\n|   Type: Local Open Directory User\n|\n", user)
		}
	}
	b.WriteString("+-- EBC6C064-0000-11AA-AA11-00306543ECAC\n|   Type: Personal Recovery User\n|\n+-- 2457C9D8-0000-11AA-AA11-00306543ECAC\n    Type: MDM Bootstrap Token External Key\n")
	return b.String()
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
	case c.name == "dscl" && len(c.args) > 1 && c.args[1] == "-deletepl": // the failed-login counter hygiene
		return nil, nil, true
	case c.name == "dscl" && len(c.args) == 4 && c.args[1] == "-read" && c.args[3] == "RealName":
		user := strings.TrimPrefix(c.args[2], "/Users/")
		if !o.exists[user] {
			return []byte("<dscl_cmd> DS Error: -14136 (eDSRecordNotFound)"), fakeExit{56}, true
		}
		name := user
		if o.realName[user] != "" {
			name = o.realName[user]
		}
		return []byte("RealName:\n " + name), nil, true
	case c.name == "dscl" && len(c.args) == 4 && c.args[1] == "-read" && c.args[3] == "IsHidden":
		user := strings.TrimPrefix(c.args[2], "/Users/")
		if !o.exists[user] {
			return []byte("<dscl_cmd> DS Error: -14136 (eDSRecordNotFound)"), fakeExit{56}, true
		}
		if hidden, known := o.hidden[user]; known {
			if hidden {
				return []byte("IsHidden: 1"), nil, true
			}
			return []byte("IsHidden: 0"), nil, true
		}
		return []byte("No such key: IsHidden"), nil, true
	case c.name == "dscl" && len(c.args) == 4 && c.args[1] == "-read" && c.args[3] == "accountPolicyData":
		user := strings.TrimPrefix(c.args[2], "/Users/")
		return []byte(fmt.Sprintf("dsAttrTypeNative:accountPolicyData:\n <plist><dict><key>failedLoginCount</key><integer>%d</integer></dict></plist>", o.failed[user])), nil, true
	case o.blocked != nil && c.name == "pwpolicy" && len(c.args) == 3 && c.args[2] == "authentication-allowed":
		user := c.args[1]
		if o.blocked[user] {
			return []byte("User <" + user + "> is not allowed to authenticate"), nil, true
		}
		return []byte("Policy allows user <" + user + "> to authenticate"), nil, true
	case c.name == "diskutil" && len(c.args) == 3 && c.args[1] == "listCryptoUsers":
		return []byte(o.cryptoUsers()), nil, true
	case c.name == "odutil":
		return nil, nil, true
	}
	return nil, nil, false
}

func TestHealAccountBridgesLastAdminGuard(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{"localadmin": true, "jdoe": true}, token: map[string]bool{"jdoe": true}}

	f := &fakeRunner{}
	f.handle = func(c call) ([]byte, error) {
		if out, err, ok := osState.handleCommon(c); ok {
			return out, err
		}
		switch {
		case c.is("sysadminctl", "-deleteUser", "localadmin"):
			if !osState.exists["laps-bridge"] {
				return []byte("Unable to delete the last admin user"), fakeExit{1}
			}
			delete(osState.exists, "localadmin")
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

	m := newTestManager(t, f)
	if err := m.healAccount(context.Background(), "localadmin", "NewPass-1"); err != nil {
		t.Fatalf("healAccount failed: %v", err)
	}

	bridgeCreated := f.indexOf("sysadminctl -addUser laps-bridge")
	targetRecreated := f.indexOf("sysadminctl -addUser localadmin")
	bridgeDeleted := f.indexOf("sysadminctl -deleteUser laps-bridge")
	if bridgeCreated < 0 || targetRecreated < 0 || bridgeDeleted < 0 {
		t.Fatalf("missing ladder steps in call sequence: %v", f.calls)
	}
	if !(bridgeCreated < targetRecreated && targetRecreated < bridgeDeleted) {
		t.Fatalf("ladder out of order (bridge %d, recreate %d, cleanup %d): the target must be recreated inside the bridge window", bridgeCreated, targetRecreated, bridgeDeleted)
	}
	if !osState.exists["localadmin"] || osState.exists["laps-bridge"] {
		t.Fatalf("end state wrong: exists=%v", osState.exists)
	}
}

func TestWithBridgeAdminReusesExistingBridge(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{"localadmin": true, "laps-bridge": true}, token: map[string]bool{}}

	f := &fakeRunner{}
	deleteAttempts := 0
	f.handle = func(c call) ([]byte, error) {
		if out, err, ok := osState.handleCommon(c); ok {
			return out, err
		}
		switch {
		case c.is("sysadminctl", "-deleteUser", "localadmin"):
			deleteAttempts++
			if deleteAttempts == 1 {
				return []byte("refused"), fakeExit{1}
			}
			delete(osState.exists, "localadmin")
			return nil, nil
		case c.is("sysadminctl", "-deleteUser", "laps-bridge"):
			delete(osState.exists, "laps-bridge")
			return nil, nil
		case c.is("dseditgroup", "-o", "checkmember", "-m", "laps-bridge", "admin"):
			return nil, nil
		case c.name == "sysadminctl" && c.args[0] == "-addUser":
			osState.exists[c.args[1]] = true
			return nil, nil
		}
		t.Fatalf("unexpected command: %s", c)
		return nil, nil
	}

	m := newTestManager(t, f)
	if err := m.healAccount(context.Background(), "localadmin", "NewPass-1"); err != nil {
		t.Fatalf("healAccount failed: %v", err)
	}
	if n := f.count("sysadminctl -addUser laps-bridge"); n != 0 {
		t.Fatalf("laps-bridge already existed but was created %d time(s)", n)
	}
}

func TestWithBridgeAdminKeepsTokenHoldingBridge(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{"localadmin": true, "laps-bridge": true}, token: map[string]bool{"laps-bridge": true}}

	f := &fakeRunner{}
	f.handle = func(c call) ([]byte, error) {
		if out, err, ok := osState.handleCommon(c); ok {
			return out, err
		}
		if c.is("dseditgroup", "-o", "checkmember", "-m", "laps-bridge", "admin") {
			return nil, nil
		}
		t.Fatalf("unexpected command: %s", c)
		return nil, nil
	}

	m := newTestManager(t, f)
	err := m.withBridgeAdmin(context.Background(), "localadmin", func() error { return nil })
	if err != nil {
		t.Fatalf("withBridgeAdmin failed: %v", err)
	}
	if f.count("sysadminctl -deleteUser laps-bridge") != 0 {
		t.Fatal("a token-holding bridge was deleted — it may have been the device's only token holder")
	}
}

func TestWithBridgeAdminKeepsBridgeWhenTargetMissing(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{"laps-bridge": true}, token: map[string]bool{}}

	f := &fakeRunner{}
	f.handle = func(c call) ([]byte, error) {
		if out, err, ok := osState.handleCommon(c); ok {
			return out, err
		}
		if c.is("dseditgroup", "-o", "checkmember", "-m", "laps-bridge", "admin") {
			return nil, nil
		}
		t.Fatalf("unexpected command: %s", c)
		return nil, nil
	}

	m := newTestManager(t, f)
	fnErr := fmt.Errorf("recreate failed")
	if err := m.withBridgeAdmin(context.Background(), "localadmin", func() error { return fnErr }); err != fnErr {
		t.Fatalf("withBridgeAdmin must surface fn's error, got: %v", err)
	}
	if f.count("sysadminctl -deleteUser laps-bridge") != 0 {
		t.Fatal("bridge deleted while the target is missing — the device would be left with no admin")
	}
}

func decodePayload(t *testing.T, c call) SwiftPayload {
	t.Helper()
	var p SwiftPayload
	if err := json.Unmarshal([]byte(c.stdin), &p); err != nil {
		t.Fatalf("mac_helper stdin is not a SwiftPayload: %v | %q", err, c.stdin)
	}
	return p
}

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
			return []byte("root 0\nlocaladminmin 501\n"), nil
		case c.name == "dscl" && c.args[1] == "-create":
			return nil, nil
		case c.name == "dscl" && c.args[1] == "-list":
			return []byte(""), nil
		case c.name == "dseditgroup":
			osState.exists["localadmin"] = true // the dscl build is what finally lands the record
			return nil, nil
		case c.name == "mac_helper":
			p := decodePayload(t, c)
			helperPayload = &p
			return []byte("[SWIFT] Administrative password reset for localadmin succeeded"), nil
		}
		t.Fatalf("unexpected command: %s", c)
		return nil, nil
	}

	m := newTestManager(t, f)
	if err := m.createHiddenAdmin(context.Background(), "localadmin", "IT Admin", realPass); err != nil {
		t.Fatalf("createHiddenAdmin failed: %v", err)
	}

	if n := f.count("sysadminctl -addUser localadmin"); n != 2 {
		t.Fatalf("expected exactly 2 sysadminctl -addUser attempts around the OD cache reset, got %d", n)
	}
	if f.indexOf("odutil reset cache") < 0 {
		t.Fatal("the OD cache reset between the two addUser attempts never happened")
	}
	if helperPayload == nil {
		t.Fatal("the dscl build never set the password through the helper")
	}
	if helperPayload.TargetPass != realPass || helperPayload.OldPass != "" || !helperPayload.AllowAdminReset {
		t.Fatalf("seal payload wrong: target=%q old=%q allowAdminReset=%v — want the real password, no old password, reset permitted", helperPayload.TargetPass, helperPayload.OldPass, helperPayload.AllowAdminReset)
	}
	for _, c := range f.calls {
		if c.name == "dscl" && len(c.args) > 1 && c.args[1] == "-passwd" {
			t.Fatalf("a password went through dscl argv: %s", c)
		}
	}
	if helper, group := f.indexOf("mac_helper"), f.indexOf("dseditgroup -o edit -a localadmin"); group < helper {
		t.Fatalf("the record joined the admin group (call %d) before its password was set (call %d)", group, helper)
	}
}

func TestCreateAdminViaDsclKeepsUnsealedRecordOutOfAdmin(t *testing.T) {
	f := &fakeRunner{}
	f.handle = func(c call) ([]byte, error) {
		switch {
		case c.is("dscl", ".", "-list", "/Users", "UniqueID"):
			return []byte("root 0\n"), nil
		case c.name == "dscl" && c.args[1] == "-create":
			return nil, nil
		case c.name == "mac_helper":
			return []byte("[SWIFT] Administrative reset for localadmin was REFUSED"), fakeExit{4}
		}
		t.Fatalf("unexpected command: %s", c)
		return nil, nil
	}
	m := newTestManager(t, f)
	if err := m.createAdminViaDscl(context.Background(), "localadmin", "IT Admin", "Real-Pass-123"); err == nil {
		t.Fatal("a refused seal must fail the build")
	}
	if f.count("dseditgroup") != 0 {
		t.Fatalf("an unsealed record was added to the admin group: %v", f.calls)
	}
}

func TestEnsureUserEscalatesFailedRotationToRecreation(t *testing.T) {
	for _, tc := range []struct {
		name        string
		code        int
		helperCalls int
	}{
		{name: "auth-failed", code: 2, helperCalls: 1},
		{name: "locked", code: 3, helperCalls: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			osState := &fakeOS{exists: map[string]bool{"localadmin": true, "jdoe": true}, token: map[string]bool{"localadmin": true, "jdoe": true}}

			f := &fakeRunner{}
			f.handle = func(c call) ([]byte, error) {
				if out, err, ok := osState.handleCommon(c); ok {
					return out, err
				}
				switch {
				case c.is("pwpolicy", "-u", "localadmin", "authentication-allowed"):
					return []byte("Password authentication is allowed"), nil
				case c.name == "mac_helper":
					p := decodePayload(t, c)
					if p.AllowAdminReset {
						t.Fatal("AllowAdminReset must stay false for a token holder")
					}
					return []byte("[SWIFT] Authenticated change failed"), fakeExit{tc.code}
				case c.is("sysadminctl", "-deleteUser", "localadmin"):
					delete(osState.exists, "localadmin")
					return nil, nil
				case c.name == "sysadminctl" && c.args[0] == "-addUser":
					osState.exists[c.args[1]] = true
					return nil, nil
				}
				t.Fatalf("unexpected command: %s", c)
				return nil, nil
			}

			m := newTestManager(t, f)
			if err := m.EnsureUserAndChangePassword(context.Background(), "localadmin", []string{"old-pass"}, "new-pass"); err != nil {
				t.Fatalf("expected escalation to recreation to succeed, got: %v", err)
			}
			if n := f.count("mac_helper"); n != tc.helperCalls {
				t.Fatalf("helper called %d time(s), want %d — every call must be an authenticated change, never an administrative reset", n, tc.helperCalls)
			}
			if f.indexOf("sysadminctl -deleteUser localadmin") < 0 || f.indexOf("sysadminctl -addUser localadmin") < 0 {
				t.Fatalf("escalation to recreation never happened: %v", f.calls)
			}
		})
	}
}

func TestEnsureUserLockedClearsCounterAndRetriesOnce(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{"localadmin": true}, token: map[string]bool{"localadmin": true}}
	f := &fakeRunner{}
	helperCalls := 0
	f.handle = func(c call) ([]byte, error) {
		if out, err, ok := osState.handleCommon(c); ok {
			return out, err
		}
		switch {
		case c.is("pwpolicy", "-u", "localadmin", "authentication-allowed"):
			return []byte("Policy allows user localadmin to authenticate"), nil
		case c.name == "mac_helper":
			helperCalls++
			if p := decodePayload(t, c); p.AllowAdminReset || p.OldPass != "old-pass" {
				t.Fatalf("retry must reuse the same authenticated candidate without a reset: %+v", p)
			}
			if helperCalls == 1 {
				return []byte("[SWIFT] Authenticated change failed (OpenDirectory code 5305, reporting locked)"), fakeExit{3}
			}
			return []byte("[SWIFT] Password natively changed"), nil
		}
		t.Fatalf("unexpected command: %s", c)
		return nil, nil
	}

	m := newTestManager(t, f)
	if err := m.EnsureUserAndChangePassword(context.Background(), "localadmin", []string{"old-pass"}, "new-pass"); err != nil {
		t.Fatalf("rotation after the counter clear failed: %v", err)
	}
	if helperCalls != 2 {
		t.Fatalf("helper called %d time(s), want exactly 2 (first locked, retry ok)", helperCalls)
	}
	clear := f.indexOf("dscl . -deletepl /Users/localadmin accountPolicyData failedLoginCount")
	if clear < 0 || clear < f.indexOf("mac_helper") {
		t.Fatalf("the counter clear must sit between the two helper calls: %v", f.calls)
	}
	if f.count("sysadminctl -deleteUser") != 0 {
		t.Fatalf("a lock that cleared must never recreate the account: %v", f.calls)
	}
}

func TestEnsureUserTokenlessRotatesInPlace(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{"localadmin": true}, token: map[string]bool{}}
	f := &fakeRunner{}
	var payload *SwiftPayload
	f.handle = func(c call) ([]byte, error) {
		if out, err, ok := osState.handleCommon(c); ok {
			return out, err
		}
		if c.name == "mac_helper" {
			p := decodePayload(t, c)
			payload = &p
			return []byte("[SWIFT] Administrative password reset for localadmin succeeded"), nil
		}
		t.Fatalf("unexpected command: %s", c)
		return nil, nil
	}

	m := newTestManager(t, f)
	if err := m.EnsureUserAndChangePassword(context.Background(), "localadmin", []string{"old-pass"}, "new-pass"); err != nil {
		t.Fatalf("in-place rotation failed: %v", err)
	}
	if payload == nil || !payload.AllowAdminReset || payload.OldPass != "old-pass" || payload.TargetPass != "new-pass" {
		t.Fatalf("token-less rotation must try the recorded password and permit the reset fallback: %+v", payload)
	}
	if f.count("sysadminctl -deleteUser") != 0 || f.count("sysadminctl -addUser") != 0 {
		t.Fatalf("a token-less account was recreated although it rotated in place: %v", f.calls)
	}
	if f.count("pwpolicy") != 0 {
		t.Fatal("the pwpolicy gate is for token holders only")
	}
}

func TestEnsureUserTokenlessResetRefusedRecreates(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{"localadmin": true}, token: map[string]bool{}}
	f := &fakeRunner{}
	f.handle = func(c call) ([]byte, error) {
		if out, err, ok := osState.handleCommon(c); ok {
			return out, err
		}
		switch {
		case c.name == "mac_helper":
			return []byte("[SWIFT] Administrative reset for localadmin was REFUSED"), fakeExit{4}
		case c.is("sysadminctl", "-deleteUser", "localadmin"):
			delete(osState.exists, "localadmin")
			return nil, nil
		case c.name == "sysadminctl" && c.args[0] == "-addUser":
			osState.exists[c.args[1]] = true
			return nil, nil
		}
		t.Fatalf("unexpected command: %s", c)
		return nil, nil
	}

	m := newTestManager(t, f)
	if err := m.EnsureUserAndChangePassword(context.Background(), "localadmin", []string{"old-pass"}, "new-pass"); err != nil {
		t.Fatalf("recreation after a refused reset failed: %v", err)
	}
	if f.indexOf("sysadminctl -deleteUser localadmin") < 0 || f.indexOf("sysadminctl -addUser localadmin") < 0 {
		t.Fatalf("a refused reset must still escalate to recreation: %v", f.calls)
	}
	if _, ok := m.lastHeal("localadmin"); !ok {
		t.Fatal("a recreation must be recorded for the cooldown")
	}
}

func TestHealAccountCooldownRefusesSecondRecreation(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{"localadmin": true}, token: map[string]bool{}}
	f := &fakeRunner{}
	f.handle = func(c call) ([]byte, error) {
		if out, err, ok := osState.handleCommon(c); ok {
			return out, err
		}
		switch {
		case c.is("sysadminctl", "-deleteUser", "localadmin"):
			delete(osState.exists, "localadmin")
			return nil, nil
		case c.name == "sysadminctl" && c.args[0] == "-addUser":
			osState.exists[c.args[1]] = true
			return nil, nil
		}
		t.Fatalf("unexpected command: %s", c)
		return nil, nil
	}

	m := newTestManager(t, f)
	if err := os.WriteFile(m.healStatePath, []byte(time.Now().Add(-26*time.Hour).UTC().Format(time.RFC3339)+" localadmin\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := m.healAccount(context.Background(), "localadmin", "new-pass")
	if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "already recreated") {
		t.Fatalf("want a [CONFLICT] refusal, got: %v", err)
	}
	if f.count("sysadminctl -deleteUser") != 0 {
		t.Fatalf("the account was deleted despite the cooldown: %v", f.calls)
	}

	if err := m.healCooldownError("laps-bridge"); err != nil {
		t.Fatalf("the cooldown leaked onto another account: %v", err)
	}
	m.now = func() time.Time { return time.Now().Add(8 * 24 * time.Hour) }
	if err := m.healAccount(context.Background(), "localadmin", "new-pass"); err != nil {
		t.Fatalf("recreation outside the cooldown failed: %v", err)
	}
	if last, ok := m.lastHeal("localadmin"); !ok || time.Since(last) > time.Minute && last.Before(time.Now()) {
		t.Fatalf("the recreation was not re-stamped: %v %v", last, ok)
	}
}

func TestHealAccountCooldownOverride(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{"localadmin": true}, token: map[string]bool{}}
	f := &fakeRunner{}
	f.handle = func(c call) ([]byte, error) {
		if out, err, ok := osState.handleCommon(c); ok {
			return out, err
		}
		switch {
		case c.is("sysadminctl", "-deleteUser", "localadmin"):
			delete(osState.exists, "localadmin")
			return nil, nil
		case c.name == "sysadminctl" && c.args[0] == "-addUser":
			osState.exists[c.args[1]] = true
			return nil, nil
		}
		t.Fatalf("unexpected command: %s", c)
		return nil, nil
	}
	m := newTestManager(t, f)
	if err := os.WriteFile(m.healStatePath, []byte(time.Now().UTC().Format(time.RFC3339)+" localadmin\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(healOverrideEnv, "1")
	if err := m.healAccount(context.Background(), "localadmin", "new-pass"); err != nil {
		t.Fatalf("the override must allow the recreation: %v", err)
	}
	if f.count("sysadminctl -deleteUser localadmin") != 1 {
		t.Fatalf("recreation did not run under the override: %v", f.calls)
	}
}

func TestEnsureUserReportsResetRefusedAsError(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{"localadmin": true}, token: map[string]bool{"localadmin": true}}

	f := &fakeRunner{}
	f.handle = func(c call) ([]byte, error) {
		if out, err, ok := osState.handleCommon(c); ok {
			return out, err
		}
		switch {
		case c.is("pwpolicy", "-u", "localadmin", "authentication-allowed"):
			return []byte("Password authentication is allowed"), nil
		case c.name == "mac_helper":
			return []byte("[SWIFT] Administrative reset was REFUSED"), fakeExit{4}
		}
		t.Fatalf("unexpected command: %s", c)
		return nil, nil
	}

	m := newTestManager(t, f)
	err := m.EnsureUserAndChangePassword(context.Background(), "localadmin", []string{"old-pass"}, "new-pass")
	if err == nil || !strings.Contains(err.Error(), "reset-refused") {
		t.Fatalf("a refused reset must fail the run with the outcome named, got: %v", err)
	}
	if f.count("sysadminctl -deleteUser localadmin") != 0 {
		t.Fatal("reset-refused must not trigger recreation on its own")
	}
}

func TestEnsureUserRecreatesWhenPwpolicyBlocksAuthentication(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{"localadmin": true, "jdoe": true}, token: map[string]bool{"localadmin": true, "jdoe": true}}

	f := &fakeRunner{}
	f.handle = func(c call) ([]byte, error) {
		if out, err, ok := osState.handleCommon(c); ok {
			return out, err
		}
		switch {
		case c.is("pwpolicy", "-u", "localadmin", "authentication-allowed"):
			return []byte("User localadmin is not allowed to authenticate until password is changed"), nil
		case c.is("sysadminctl", "-deleteUser", "localadmin"):
			delete(osState.exists, "localadmin")
			return nil, nil
		case c.name == "sysadminctl" && c.args[0] == "-addUser":
			osState.exists[c.args[1]] = true
			return nil, nil
		}
		t.Fatalf("unexpected command: %s", c)
		return nil, nil
	}

	m := newTestManager(t, f)
	if err := m.EnsureUserAndChangePassword(context.Background(), "localadmin", []string{"old-pass"}, "new-pass"); err != nil {
		t.Fatalf("recreation after a pwpolicy block failed: %v", err)
	}
	if f.count("mac_helper") != 0 {
		t.Fatal("the helper must not be asked to rotate an account pwpolicy already declared blocked")
	}
}

func TestEnsureUserPwpolicyGateIgnoresErrorOutput(t *testing.T) {
	for _, tt := range []struct {
		name   string
		out    string
		outErr error
	}{
		{name: "error text carrying both not and allowed", out: "Error: command not allowed against the directory service", outErr: fmt.Errorf("exit 1")},
		{name: "healthy verdict", out: "Policy allows user localadmin to authenticate", outErr: nil},
		{name: "no output at all", out: "", outErr: fmt.Errorf("signal: killed")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			osState := &fakeOS{exists: map[string]bool{"localadmin": true}, token: map[string]bool{"localadmin": true}}

			f := &fakeRunner{}
			f.handle = func(c call) ([]byte, error) {
				if out, err, ok := osState.handleCommon(c); ok {
					return out, err
				}
				switch {
				case c.is("pwpolicy", "-u", "localadmin", "authentication-allowed"):
					return []byte(tt.out), tt.outErr
				case c.name == "mac_helper":
					return []byte("[SWIFT] change ok"), nil
				}
				t.Fatalf("unexpected command: %s", c)
				return nil, nil
			}

			m := newTestManager(t, f)
			if err := m.EnsureUserAndChangePassword(context.Background(), "localadmin", []string{"old-pass"}, "new-pass"); err != nil {
				t.Fatalf("rotation failed: %v", err)
			}
			if f.count("sysadminctl -deleteUser localadmin") != 0 {
				t.Fatal("a pwpolicy error/healthy output must never trigger account recreation")
			}
			if f.count("mac_helper") == 0 {
				t.Fatal("rotation must proceed through the helper when the gate does not fire")
			}
		})
	}
}

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
	osState := &fakeOS{exists: map[string]bool{"localadmin": true}, token: map[string]bool{}}
	f := &fakeRunner{}
	f.handle = btCoveredHandler(osState, "true", nil, profilesEscrowedYES, nil)
	m := newTestManager(t, f)
	prompted := false
	m.prompt = func(context.Context, string, string) promptResult {
		prompted = true
		return promptResult{outcome: passwordUnavailable}
	}

	status := m.ManageSecureToken(context.Background(), "localadmin", "newpass", map[string]string{})
	if status != TokenStatusDisabledCovered {
		t.Fatalf("status = %q, want %q", status, TokenStatusDisabledCovered)
	}
	if !prompted {
		t.Fatal("the GUI prompt was skipped: coverage must not cancel token restoration")
	}
	if f.count("fdesetup haspersonalrecoverykey") != 1 || f.count("profiles status -type bootstraptoken") != 1 {
		t.Fatalf("coverage checks not performed exactly once: %v", f.calls)
	}
}

func TestRecoveryCoveredByMDMSucceedsInsideReserveWindow(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{"localadmin": true}, token: map[string]bool{}}
	f := &fakeRunner{}
	f.handle = btCoveredHandler(osState, "true", nil, profilesEscrowedYES, nil)
	m := newTestManager(t, f)

	ctx, cancel := context.WithTimeout(context.Background(), vaultWriteReserve-30*time.Second)
	defer cancel()

	if !m.recoveryCoveredByMDM(ctx) {
		t.Fatal("recoveryCoveredByMDM returned false when remaining run budget was inside vaultWriteReserve")
	}
}

func TestManageSecureTokenPromptSuccessNeedsNoCoverageCheck(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{"localadmin": true}, token: map[string]bool{}}
	f := &fakeRunner{}
	f.handle = btCoveredHandler(osState, "true", nil, profilesEscrowedYES, nil)
	m := newTestManager(t, f)
	m.prompt = func(context.Context, string, string) promptResult { return promptResult{outcome: passwordOK} }

	if status := m.ManageSecureToken(context.Background(), "localadmin", "newpass", map[string]string{}); status != "ENABLED (Via GUI Prompt)" {
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
			if newTestManager(t, f).recoveryCoveredByMDM(context.Background()) {
				t.Fatalf("recovery must read as NOT covered")
			}
		})
	}
}

func TestManageSecureTokenUncoveredStaysRed(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{"localadmin": true}, token: map[string]bool{}}
	f := &fakeRunner{}
	f.handle = btCoveredHandler(osState, "false", nil, "profiles: something unhelpful", nil)
	m := newTestManager(t, f)

	if status := m.ManageSecureToken(context.Background(), "localadmin", "newpass", map[string]string{}); status != "DISABLED (Review Required)" {
		t.Fatalf("status = %q, want the red Review Required status on an uncovered device", status)
	}
}

func TestEnsureUserPolicyRejectedDoesNotRecreate(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{"localadmin": true}, token: map[string]bool{"localadmin": true}}
	f := &fakeRunner{}
	f.handle = func(c call) ([]byte, error) {
		if out, err, ok := osState.handleCommon(c); ok {
			return out, err
		}
		switch {
		case c.is("pwpolicy", "-u", "localadmin", "authentication-allowed"):
			return []byte("Password authentication is allowed"), nil
		case c.name == "mac_helper":
			return []byte("[SWIFT] policy rejected the new password"), fakeExit{5}
		}
		t.Fatalf("unexpected command: %s", c)
		return nil, nil
	}

	m := newTestManager(t, f)
	err := m.EnsureUserAndChangePassword(context.Background(), "localadmin", []string{"old-pass"}, "new-pass")
	if !errors.Is(err, ErrPolicyRejected) {
		t.Fatalf("want ErrPolicyRejected, got: %v", err)
	}
	if f.count("sysadminctl -deleteUser") != 0 {
		t.Fatalf("a policy-rejected rotation recreated a healthy admin: %v", f.calls)
	}
}

func TestEnsureUserTriesStagedPasswordBeforeRecreation(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{"localadmin": true}, token: map[string]bool{"localadmin": true}}
	f := &fakeRunner{}
	var oldPasses []string
	f.handle = func(c call) ([]byte, error) {
		if out, err, ok := osState.handleCommon(c); ok {
			return out, err
		}
		switch {
		case c.is("pwpolicy", "-u", "localadmin", "authentication-allowed"):
			return []byte("Password authentication is allowed"), nil
		case c.name == "mac_helper":
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

	m := newTestManager(t, f)
	if err := m.EnsureUserAndChangePassword(context.Background(), "localadmin", []string{"stale-recorded", "staged-live"}, "new-pass"); err != nil {
		t.Fatalf("the staged fallback should have completed the rotation: %v", err)
	}
	if len(oldPasses) != 2 || oldPasses[0] != "stale-recorded" || oldPasses[1] != "staged-live" {
		t.Fatalf("expected recorded-then-staged attempts, got %v", oldPasses)
	}
	if f.count("sysadminctl -deleteUser") != 0 {
		t.Fatalf("recreation happened despite the staged password working: %v", f.calls)
	}
}

func TestEnsureUserLockRetryUsesTheLockedCandidate(t *testing.T) {
	type step struct {
		oldPass string // the candidate the helper must receive
		code    int    // the outcome the helper returns (0 ok, 2 auth-failed, 3 locked)
	}
	for _, tc := range []struct {
		name       string
		steps      []step
		wantHeal   bool
		wantClears int
	}{
		{
			name:       "locked primary then alternate",
			steps:      []step{{"recorded", 3}, {"recorded", 2}, {"staged", 0}},
			wantClears: 1,
		},
		{
			name:       "locked alternate is retried itself",
			steps:      []step{{"recorded", 2}, {"staged", 3}, {"staged", 0}},
			wantClears: 1,
		},
		{
			name:       "both wrong after the clear recreate",
			steps:      []step{{"recorded", 3}, {"recorded", 2}, {"staged", 2}},
			wantHeal:   true,
			wantClears: 1,
		},
		{
			name:       "persistent lock recreates without a second clear",
			steps:      []step{{"recorded", 3}, {"recorded", 3}},
			wantHeal:   true,
			wantClears: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			osState := &fakeOS{exists: map[string]bool{"localadmin": true, "jdoe": true}, token: map[string]bool{"localadmin": true, "jdoe": true}}
			f := &fakeRunner{}
			helperCalls := 0
			clears := 0
			f.handle = func(c call) ([]byte, error) {
				if c.is("dscl", ".", "-deletepl", "/Users/localadmin", "accountPolicyData", "failedLoginCount") {
					clears++
				}
				if out, err, ok := osState.handleCommon(c); ok {
					return out, err
				}
				switch {
				case c.is("pwpolicy", "-u", "localadmin", "authentication-allowed"):
					return []byte("Policy allows user localadmin to authenticate"), nil
				case c.name == "mac_helper":
					p := decodePayload(t, c)
					if p.AllowAdminReset {
						t.Fatalf("AllowAdminReset must stay false for a token holder: %+v", p)
					}
					if helperCalls >= len(tc.steps) {
						t.Fatalf("helper call %d is one too many: %+v", helperCalls+1, p)
					}
					want := tc.steps[helperCalls]
					helperCalls++
					if p.OldPass != want.oldPass {
						t.Fatalf("helper call %d got candidate %q, want %q", helperCalls, p.OldPass, want.oldPass)
					}
					switch want.code {
					case 0:
						return []byte("[SWIFT] Password natively changed"), nil
					case 3:
						return []byte("[SWIFT] Authenticated change failed (OpenDirectory code 5305, reporting locked)"), fakeExit{3}
					default:
						return []byte("[SWIFT] Authenticated change failed"), fakeExit{2}
					}
				case c.is("sysadminctl", "-deleteUser", "localadmin"):
					delete(osState.exists, "localadmin")
					return nil, nil
				case c.name == "sysadminctl" && c.args[0] == "-addUser":
					osState.exists[c.args[1]] = true
					return nil, nil
				}
				t.Fatalf("unexpected command: %s", c)
				return nil, nil
			}

			m := newTestManager(t, f)
			if err := m.EnsureUserAndChangePassword(context.Background(), "localadmin", []string{"recorded", "staged"}, "new-pass"); err != nil {
				t.Fatalf("rotation failed: %v", err)
			}
			if helperCalls != len(tc.steps) {
				t.Fatalf("helper called %d time(s), want %d", helperCalls, len(tc.steps))
			}
			if clears != tc.wantClears {
				t.Fatalf("counter cleared %d time(s) during the rotation, want %d: %v", clears, tc.wantClears, f.calls)
			}
			if healed := f.count("sysadminctl -deleteUser localadmin") == 1; healed != tc.wantHeal {
				t.Fatalf("recreation happened=%v, want %v: %v", healed, tc.wantHeal, f.calls)
			}
		})
	}
}

func TestEnsureUserThirdCandidateAuthenticatesWithoutRecreation(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{"localadmin": true}, token: map[string]bool{"localadmin": true}}
	f := &fakeRunner{}
	var oldPasses []string
	f.handle = func(c call) ([]byte, error) {
		if out, err, ok := osState.handleCommon(c); ok {
			return out, err
		}
		switch {
		case c.is("pwpolicy", "-u", "localadmin", "authentication-allowed"):
			return []byte("Policy allows user localadmin to authenticate"), nil
		case c.name == "mac_helper":
			p := decodePayload(t, c)
			if p.AllowAdminReset {
				t.Fatalf("AllowAdminReset must stay false for a token holder: %+v", p)
			}
			oldPasses = append(oldPasses, p.OldPass)
			if p.OldPass == "recorded" {
				return []byte("[SWIFT] Password natively changed"), nil
			}
			return []byte("[SWIFT] Authenticated change failed"), fakeExit{2}
		}
		t.Fatalf("unexpected command: %s", c)
		return nil, nil
	}

	m := newTestManager(t, f)
	if err := m.EnsureUserAndChangePassword(context.Background(), "localadmin", []string{"pending", "previous-pending", "recorded"}, "new-pass"); err != nil {
		t.Fatalf("rotation failed: %v", err)
	}
	want := []string{"pending", "previous-pending", "recorded"}
	if strings.Join(oldPasses, ",") != strings.Join(want, ",") {
		t.Fatalf("helper received candidates %v, want %v in that order", oldPasses, want)
	}
	if f.count("sysadminctl -deleteUser") != 0 {
		t.Fatalf("recreation happened although the third candidate authenticated: %v", f.calls)
	}
}

func TestEnsureUserLegacyCandidateReachesTheHelperLast(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{"localadmin": true}, token: map[string]bool{"localadmin": true}}
	f := &fakeRunner{}
	var oldPasses []string
	f.handle = func(c call) ([]byte, error) {
		if out, err, ok := osState.handleCommon(c); ok {
			return out, err
		}
		switch {
		case c.is("pwpolicy", "-u", "localadmin", "authentication-allowed"):
			return []byte("Policy allows user localadmin to authenticate"), nil
		case c.name == "mac_helper":
			p := decodePayload(t, c)
			oldPasses = append(oldPasses, p.OldPass)
			if p.OldPass == "enrollment" {
				return []byte("[SWIFT] Password natively changed"), nil
			}
			return []byte("[SWIFT] Authenticated change failed"), fakeExit{2}
		case c.is("sysadminctl", "-deleteUser", "localadmin"):
			t.Fatal("recreation ran before the legacy candidate had its turn")
		}
		t.Fatalf("unexpected command: %s", c)
		return nil, nil
	}

	m := newTestManager(t, f)
	if err := m.EnsureUserAndChangePassword(context.Background(), "localadmin", []string{"previous-owner", "enrollment"}, "new-pass"); err != nil {
		t.Fatalf("rotation failed: %v", err)
	}
	if len(oldPasses) != 2 || oldPasses[len(oldPasses)-1] != "enrollment" {
		t.Fatalf("helper received %v, want the enrollment password as the last candidate", oldPasses)
	}
}

func TestEnsureUserTokenlessTriesEveryCandidateBeforeTheReset(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{"localadmin": true}, token: map[string]bool{}}
	f := &fakeRunner{}
	var payloads []SwiftPayload
	f.handle = func(c call) ([]byte, error) {
		if out, err, ok := osState.handleCommon(c); ok {
			return out, err
		}
		if c.name == "mac_helper" {
			p := decodePayload(t, c)
			payloads = append(payloads, p)
			if p.OldPass == "recorded" {
				return []byte("[SWIFT] Password natively changed"), nil
			}
			return []byte("[SWIFT] Authenticated change failed"), fakeExit{2}
		}
		t.Fatalf("unexpected command: %s", c)
		return nil, nil
	}

	m := newTestManager(t, f)
	if err := m.EnsureUserAndChangePassword(context.Background(), "localadmin", []string{"pending", "recorded", "legacy"}, "new-pass"); err != nil {
		t.Fatalf("in-place rotation failed: %v", err)
	}
	if len(payloads) != 2 {
		t.Fatalf("helper called %d time(s), want 2 (pending fails, recorded works): %+v", len(payloads), payloads)
	}
	if payloads[0].OldPass != "pending" || payloads[0].AllowAdminReset {
		t.Fatalf("first call must try the pending candidate without a reset: %+v", payloads[0])
	}
	if payloads[1].OldPass != "recorded" || payloads[1].AllowAdminReset {
		t.Fatalf("second call must try the recorded candidate without a reset: %+v", payloads[1])
	}
	if f.count("sysadminctl -deleteUser") != 0 {
		t.Fatalf("a token-less account was recreated although a candidate authenticated: %v", f.calls)
	}
}

func TestEnsureUserTokenlessResetOnlyOnTheLastCandidate(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{"localadmin": true}, token: map[string]bool{}}
	f := &fakeRunner{}
	var payloads []SwiftPayload
	f.handle = func(c call) ([]byte, error) {
		if out, err, ok := osState.handleCommon(c); ok {
			return out, err
		}
		if c.name == "mac_helper" {
			p := decodePayload(t, c)
			payloads = append(payloads, p)
			if p.AllowAdminReset {
				return []byte("[SWIFT] Administrative password reset for localadmin succeeded"), nil
			}
			return []byte("[SWIFT] Authenticated change failed"), fakeExit{2}
		}
		t.Fatalf("unexpected command: %s", c)
		return nil, nil
	}

	m := newTestManager(t, f)
	if err := m.EnsureUserAndChangePassword(context.Background(), "localadmin", []string{"pending", "legacy"}, "new-pass"); err != nil {
		t.Fatalf("in-place rotation failed: %v", err)
	}
	if len(payloads) != 2 || payloads[0].AllowAdminReset || !payloads[1].AllowAdminReset || payloads[1].OldPass != "legacy" {
		t.Fatalf("want two calls, reset permitted on the last candidate only: %+v", payloads)
	}
}

func TestCreateHiddenAdminRedactsPasswordInError(t *testing.T) {
	const pass = "Echoed-Secret-42"
	f := &fakeRunner{}
	f.handle = func(c call) ([]byte, error) {
		if c.name == "sysadminctl" && c.args[0] == "-addUser" {
			return []byte("sysadminctl[1]: OD error 5000 for password " + pass + " on localadmin"), fakeExit{1}
		}
		t.Fatalf("unexpected command: %s", c)
		return nil, nil
	}
	m := newTestManager(t, f)

	var err error
	logged := captureLog(func() { err = m.createHiddenAdmin(context.Background(), "localadmin", "IT Admin", pass) })

	if err == nil {
		t.Fatal("a failed -addUser must be an error")
	}
	if strings.Contains(err.Error(), pass) {
		t.Fatalf("the password is in the returned error: %v", err)
	}
	if strings.Contains(logged, pass) {
		t.Fatalf("the password is in the log:\n%s", logged)
	}
	if !strings.Contains(err.Error(), "[REDACTED]") {
		t.Fatalf("the error must keep the output with the password masked, got: %v", err)
	}
}

func soleAccountOS(t *testing.T, jdoeToken, jdoeAdmin bool) (*fakeRunner, *fakeOS) {
	t.Helper()
	osState := &fakeOS{exists: map[string]bool{"localadmin": true, "jdoe": true}, token: map[string]bool{"localadmin": true, "jdoe": jdoeToken}}
	f := &fakeRunner{}
	f.handle = func(c call) ([]byte, error) {
		if out, err, ok := osState.handleCommon(c); ok {
			return out, err
		}
		switch {
		case c.is("dscl", ".", "-list", "/Users", "UniqueID"):
			return []byte("localadmin  501\njdoe  502\n"), nil
		case c.is("dseditgroup", "-o", "checkmember", "-m", "jdoe", "admin"):
			if jdoeAdmin {
				return []byte("yes jdoe is a member of admin"), nil
			}
			return []byte("no jdoe is NOT a member of admin"), fakeExit{67}
		case c.is("sysadminctl", "-deleteUser", "localadmin"):
			delete(osState.exists, "localadmin")
			return nil, nil
		case c.name == "sysadminctl" && c.args[0] == "-addUser":
			osState.exists[c.args[1]] = true
			return nil, nil
		}
		t.Fatalf("unexpected command: %s", c)
		return nil, nil
	}
	return f, osState
}

func TestHealAccountRefusesSoleAccount(t *testing.T) {
	f, osState := soleAccountOS(t, false, false)
	m := newTestManager(t, f)
	m.escrowBridge = func(context.Context, string) error {
		t.Fatal("no bridge password may be escrowed for a sole account")
		return nil
	}

	var err error
	logged := captureLog(func() { err = m.healAccount(context.Background(), "localadmin", "NewPass-1") })

	const want = "[SOLE ACCOUNT] localadmin is the only admin and the only Secure Token holder; macOS refuses to delete it. Recreation is impossible. Check the vault record: a reassigned or re-enrolled Mac still carries the previous owner's password; the legacy enrollment password is tried last."
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("got %v, want the sole-account refusal", err)
	}
	if !strings.Contains(logged, want) {
		t.Fatalf("missing the [SOLE ACCOUNT] line in the log:\n%s", logged)
	}
	if n := f.count("sysadminctl -deleteUser"); n != 0 {
		t.Fatalf("deleteUser ran %d time(s) on a sole account: %v", n, f.calls)
	}
	if n := f.count("sysadminctl -addUser"); n != 0 {
		t.Fatalf("%d account(s) created on a sole-account Mac: %v", n, f.calls)
	}
	if !osState.exists["localadmin"] {
		t.Fatal("the target must stay")
	}
	if _, err := os.Stat(m.healStatePath); !os.IsNotExist(err) {
		t.Fatal("a refused heal must not count as a recreation for the cooldown")
	}
}

func TestHealAccountProceedsWhenAnotherAccountCanHoldTheMac(t *testing.T) {
	for _, tt := range []struct {
		name      string
		jdoeToken bool
		jdoeAdmin bool
	}{
		{name: "a second token holder", jdoeToken: true},
		{name: "a second admin without a token", jdoeAdmin: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f, osState := soleAccountOS(t, tt.jdoeToken, tt.jdoeAdmin)
			m := newTestManager(t, f)

			var err error
			logged := captureLog(func() { err = m.healAccount(context.Background(), "localadmin", "NewPass-1") })

			if err != nil {
				t.Fatalf("the heal must proceed: %v", err)
			}
			if strings.Contains(logged, "[SOLE ACCOUNT]") {
				t.Fatalf("the sole-account guard fired although another account can hold the Mac:\n%s", logged)
			}
			if f.count("sysadminctl -deleteUser localadmin") != 1 || f.count("sysadminctl -addUser localadmin") != 1 {
				t.Fatalf("expected one deletion and one creation of localadmin: %v", f.calls)
			}
			if !osState.exists["localadmin"] {
				t.Fatal("localadmin must exist after the heal")
			}
		})
	}
}

func TestVerifyPasswordReportsHelperVerdict(t *testing.T) {
	for _, tc := range []struct {
		name    string
		code    int
		want    bool
		wantErr bool
	}{
		{name: "exit 0 is live", code: 0, want: true},
		{name: "exit 2 is not live", code: 2, want: false},
		{name: "exit 1 is an OpenDirectory error and proves nothing", code: 1, wantErr: true},
		{name: "exit 3 is a locked account and proves nothing", code: 3, wantErr: true},
		{name: "an unknown exit proves nothing", code: 9, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeRunner{}
			var seen SwiftPayload
			f.handle = func(c call) ([]byte, error) {
				if c.name != "mac_helper" {
					t.Fatalf("unexpected command: %s", c)
				}
				seen = decodePayload(t, c)
				if tc.code == 0 {
					return []byte("[SWIFT] Password verified"), nil
				}
				return []byte("[SWIFT] Password rejected"), fakeExit{tc.code}
			}
			ok, err := newTestManager(t, f).VerifyPassword(context.Background(), "localadmin", "candidate-1")
			if tc.wantErr {
				if err == nil || ok {
					t.Fatalf("exit %d must be an error and never a proven wrong password, got ok=%v err=%v", tc.code, ok, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("VerifyPassword returned an error for a helper verdict: %v", err)
			}
			if ok != tc.want {
				t.Fatalf("VerifyPassword = %v, want %v", ok, tc.want)
			}
			if seen.Action != "verify_password" || seen.TargetUser != "localadmin" || seen.TargetPass != "candidate-1" {
				t.Fatalf("helper payload = %+v, want a verify_password for localadmin with the candidate", seen)
			}
			if len(f.calls) != 1 || len(f.calls[0].args) != 0 {
				t.Fatalf("the password must travel on stdin only, got %v", f.calls)
			}
		})
	}

	t.Run("helper could not run", func(t *testing.T) {
		f := &fakeRunner{}
		f.handle = func(c call) ([]byte, error) { return nil, errors.New("fork/exec: no such file") }
		ok, err := newTestManager(t, f).VerifyPassword(context.Background(), "localadmin", "candidate-1")
		if err == nil || ok {
			t.Fatalf("a helper that could not run must be an error, got ok=%v err=%v", ok, err)
		}
	})

	t.Run("untrusted helper receives nothing", func(t *testing.T) {
		f := &fakeRunner{}
		f.handle = func(c call) ([]byte, error) { t.Fatalf("the helper ran: %s", c); return nil, nil }
		m := newTestManager(t, f)
		tree := rootOwnedTree(helperPath)
		tree[helperPath] = fakeFileInfo{name: "mac_helper", mode: 0o755, uid: 501}
		m.lstat = fakeTree(tree)
		if ok, err := m.VerifyPassword(context.Background(), "localadmin", "candidate-1"); err == nil || ok {
			t.Fatalf("an untrusted helper must fail the check, got ok=%v err=%v", ok, err)
		}
	})
}

func TestEnsureUserEmptyCandidateListStillAttemptsTheChange(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{"localadmin": true, "jdoe": true}, token: map[string]bool{"localadmin": true, "jdoe": true}}
	f := &fakeRunner{}
	var oldPasses []string
	f.handle = func(c call) ([]byte, error) {
		if out, err, ok := osState.handleCommon(c); ok {
			return out, err
		}
		switch {
		case c.is("pwpolicy", "-u", "localadmin", "authentication-allowed"):
			return []byte("Password authentication is allowed"), nil
		case c.name == "mac_helper":
			p := decodePayload(t, c)
			oldPasses = append(oldPasses, p.OldPass)
			return []byte("[SWIFT] Authenticated change failed"), fakeExit{2}
		case c.is("sysadminctl", "-deleteUser", "localadmin"):
			delete(osState.exists, "localadmin")
			return nil, nil
		case c.name == "sysadminctl" && c.args[0] == "-addUser":
			osState.exists[c.args[1]] = true
			return nil, nil
		}
		t.Fatalf("unexpected command: %s", c)
		return nil, nil
	}

	m := newTestManager(t, f)
	if err := m.EnsureUserAndChangePassword(context.Background(), "localadmin", nil, "new-pass"); err != nil {
		t.Fatalf("the escalation must still succeed: %v", err)
	}
	if len(oldPasses) != 1 || oldPasses[0] != "" {
		t.Fatalf("helper received %q, want exactly one attempt with an empty password", oldPasses)
	}
	if f.indexOf("sysadminctl -deleteUser localadmin") < 0 {
		t.Fatalf("an empty list must escalate like a wrong password, got: %v", f.calls)
	}
}

func windowPrompt(t *testing.T, m *MacOSManager, f *fakeRunner, correct string, wins ...*fakeWindow) {
	t.Helper()
	inner := f.handle
	f.handle = func(c call) ([]byte, error) {
		switch {
		case c.name == "ioreg":
			return []byte(ioregUnlocked), nil
		case c.is("dseditgroup", "-o", "checkmember", "-m", "alice", "admin"):
			return []byte("yes alice is a member of admin"), nil
		case c.name == "mac_helper" && decodePayload(t, c).Action == "verify_password":
			p := decodePayload(t, c)
			if p.TargetUser == "alice" && p.TargetPass == correct {
				return nil, nil
			}
			return nil, fakeExit{1}
		}
		return inner(c)
	}
	m.promptStatePath = filepath.Join(t.TempDir(), "golaps", "token_prompt.json")
	m.openApp = func(context.Context, string, string, string) error { return nil }
	m.openWindow = func(context.Context, string, string, dialogRequest) (passwordWindow, error) {
		if len(wins) == 0 {
			t.Fatal("ManageSecureToken opened more windows than the test scripted")
		}
		win := wins[0]
		wins = wins[1:]
		return win, nil
	}
	m.prompt = func(ctx context.Context, targetUser, newPass string) promptResult {
		outcome, tally := m.askPassword(ctx, "501", "alice", false, func(context.Context, string) error { return nil })
		return promptResult{outcome: outcome, user: "alice", wrongPasswordRuns: tally.wrongPasswordRuns, windowFailedRuns: tally.windowFailedRuns, windowFailed: tally.windowFailed}
	}
}

func TestManageSecureTokenWrongPasswordStreakTurnsRed(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{"localadmin": true}, token: map[string]bool{}}
	f := &fakeRunner{}
	f.handle = btCoveredHandler(osState, "true", nil, profilesEscrowedYES, nil)
	m := newTestManager(t, f)
	windowPrompt(t, m, f, "correct horse", &fakeWindow{events: wrongFive()}, &fakeWindow{events: wrongFive()}, &fakeWindow{events: wrongFive()})

	var first, second string
	logged := captureLog(func() { first = m.ManageSecureToken(context.Background(), "localadmin", "newpass", map[string]string{}) })
	if first != TokenStatusDisabledCovered {
		t.Fatalf("first run: status = %q, want %q", first, TokenStatusDisabledCovered)
	}
	if strings.Contains(logged, "[WRONG PASSWORD STREAK]") {
		t.Errorf("the first run is not a streak yet: %s", logged)
	}
	if st := readState(t, m); st.WrongPasswordRuns != 1 {
		t.Fatalf("streak after the first run = %d, want 1", st.WrongPasswordRuns)
	}

	logged = captureLog(func() { second = m.ManageSecureToken(context.Background(), "localadmin", "newpass", map[string]string{}) })
	if second != TokenStatusDisabledWrongPassword {
		t.Fatalf("second run: status = %q, want %q", second, TokenStatusDisabledWrongPassword)
	}
	if !strings.Contains(logged, "[WRONG PASSWORD STREAK] alice entered a wrong password in each of 5 attempts in 2 consecutive runs; IT follow-up is needed.") {
		t.Errorf("the second run has no streak line: %s", logged)
	}
	if !strings.Contains(logged, "PROMPT: wrong-password") {
		t.Errorf("the PROMPT word must stay wrong-password: %s", logged)
	}
	if f.count("fdesetup haspersonalrecoverykey") != 1 {
		t.Errorf("coverage was checked %d time(s), want once: coverage does not soften a streak", f.count("fdesetup haspersonalrecoverykey"))
	}
	if st := readState(t, m); st.WrongPasswordRuns != 2 {
		t.Errorf("streak after the second run = %d, want 2", st.WrongPasswordRuns)
	}

	if third := m.ManageSecureToken(context.Background(), "localadmin", "newpass", map[string]string{}); third != TokenStatusDisabledWrongPassword {
		t.Errorf("third run: status = %q, want %q", third, TokenStatusDisabledWrongPassword)
	}
}

func TestManageSecureTokenWindowFailedStreakTurnsRed(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{"localadmin": true}, token: map[string]bool{}}
	f := &fakeRunner{}
	f.handle = btCoveredHandler(osState, "true", nil, profilesEscrowedYES, nil)
	m := newTestManager(t, f)
	killed := func() *fakeWindow { return &fakeWindow{events: []any{errors.New("signal: terminated")}} }
	windowPrompt(t, m, f, "correct horse", killed(), killed(), &fakeWindow{events: []any{typed("correct horse")}}, killed())

	var first, second string
	logged := captureLog(func() { first = m.ManageSecureToken(context.Background(), "localadmin", "newpass", map[string]string{}) })
	if first != TokenStatusDisabledCovered {
		t.Fatalf("first run: status = %q, want %q", first, TokenStatusDisabledCovered)
	}
	if strings.Contains(logged, "[WINDOW ENDED STREAK]") {
		t.Errorf("the first run is not a streak yet: %s", logged)
	}
	if st := readState(t, m); st.WindowFailedRuns != 1 {
		t.Fatalf("streak after the first run = %d, want 1", st.WindowFailedRuns)
	}

	logged = captureLog(func() { second = m.ManageSecureToken(context.Background(), "localadmin", "newpass", map[string]string{}) })
	if second != TokenStatusDisabledWindowKilled {
		t.Fatalf("second run: status = %q, want %q", second, TokenStatusDisabledWindowKilled)
	}
	if !strings.Contains(logged, "[WINDOW ENDED STREAK] alice ended the password window before an answer in 2 consecutive runs; IT follow-up is needed.") {
		t.Errorf("the second run has no streak line: %s", logged)
	}
	if !strings.Contains(logged, "PROMPT: window-failed") {
		t.Errorf("the PROMPT word must stay window-failed: %s", logged)
	}

	if status := m.ManageSecureToken(context.Background(), "localadmin", "newpass", map[string]string{}); status != "ENABLED (Via GUI Prompt)" {
		t.Fatalf("third run: status = %q, want the GUI-grant success", status)
	}
	if status := m.ManageSecureToken(context.Background(), "localadmin", "newpass", map[string]string{}); status != TokenStatusDisabledCovered {
		t.Errorf("fourth run: status = %q, want %q: the grant reset the streak", status, TokenStatusDisabledCovered)
	}
}

func TestManageSecureTokenWindowKilledBeforeItAppearsTurnsRed(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{"localadmin": true}, token: map[string]bool{}}
	f := &fakeRunner{}
	f.handle = btCoveredHandler(osState, "true", nil, profilesEscrowedYES, nil)
	m := newTestManager(t, f)
	killedEarly := func() *fakeWindow { return &fakeWindow{neverShown: true, events: []any{io.EOF}} }
	windowPrompt(t, m, f, "correct horse", killedEarly(), killedEarly())

	if first := m.ManageSecureToken(context.Background(), "localadmin", "newpass", map[string]string{}); first != TokenStatusDisabledCovered {
		t.Fatalf("first run: status = %q, want %q", first, TokenStatusDisabledCovered)
	}
	var second string
	logged := captureLog(func() { second = m.ManageSecureToken(context.Background(), "localadmin", "newpass", map[string]string{}) })
	if second != TokenStatusDisabledWindowKilled {
		t.Fatalf("second run: status = %q, want %q", second, TokenStatusDisabledWindowKilled)
	}
	if !strings.Contains(logged, "[WINDOW ENDED STREAK]") || !strings.Contains(logged, "PROMPT: window-failed") {
		t.Errorf("the second run needs the streak line and the window-failed word: %s", logged)
	}
}

func TestManageSecureTokenWindowStartFailureIsNotAStreakRun(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{"localadmin": true}, token: map[string]bool{}}
	f := &fakeRunner{}
	f.handle = btCoveredHandler(osState, "true", nil, profilesEscrowedYES, nil)
	m := newTestManager(t, f)
	windowPrompt(t, m, f, "correct horse")
	writeState(t, m, `{"user":"alice","first_prompt":"2026-11-10T09:00:00Z","deferrals":3,"unanswered":2,"window_failed_runs":2}`)
	m.openWindow = func(context.Context, string, string, dialogRequest) (passwordWindow, error) {
		return nil, errors.New("the password window is not installed or not trusted")
	}

	if status := m.ManageSecureToken(context.Background(), "localadmin", "newpass", map[string]string{}); status != TokenStatusDisabledCovered {
		t.Fatalf("status = %q, want %q", status, TokenStatusDisabledCovered)
	}
	if st := readState(t, m); st.WindowFailedRuns != 2 {
		t.Errorf("streak = %d, want 2 unchanged", st.WindowFailedRuns)
	}
}

func TestManageSecureTokenGrantEndsTheWrongPasswordStreak(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{"localadmin": true}, token: map[string]bool{}}
	f := &fakeRunner{}
	f.handle = btCoveredHandler(osState, "true", nil, profilesEscrowedYES, nil)
	m := newTestManager(t, f)
	windowPrompt(t, m, f, "correct horse", &fakeWindow{events: wrongFive()}, &fakeWindow{events: []any{typed("correct horse")}}, &fakeWindow{events: wrongFive()})

	if status := m.ManageSecureToken(context.Background(), "localadmin", "newpass", map[string]string{}); status != TokenStatusDisabledCovered {
		t.Fatalf("first run: status = %q, want %q", status, TokenStatusDisabledCovered)
	}
	if status := m.ManageSecureToken(context.Background(), "localadmin", "newpass", map[string]string{}); status != "ENABLED (Via GUI Prompt)" {
		t.Fatalf("second run: status = %q, want the GUI-grant success", status)
	}
	if _, err := os.Stat(m.promptStatePath); !os.IsNotExist(err) {
		t.Fatal("the record stayed after the grant")
	}
	if status := m.ManageSecureToken(context.Background(), "localadmin", "newpass", map[string]string{}); status != TokenStatusDisabledCovered {
		t.Errorf("third run: status = %q, want %q: the grant reset the streak", status, TokenStatusDisabledCovered)
	}
}

func TestManageSecureTokenExistingTokenEndsTheWrongPasswordStreak(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{"localadmin": true}, token: map[string]bool{"localadmin": true}}
	f := &fakeRunner{}
	f.handle = btCoveredHandler(osState, "true", nil, profilesEscrowedYES, nil)
	m := newTestManager(t, f)
	windowPrompt(t, m, f, "correct horse")
	writeState(t, m, streakState(3, 0))

	if status := m.ManageSecureToken(context.Background(), "localadmin", "newpass", map[string]string{}); !strings.HasPrefix(status, "ENABLED") {
		t.Fatalf("status = %q, want ENABLED", status)
	}
	if _, err := os.Stat(m.promptStatePath); !os.IsNotExist(err) {
		t.Error("the record stayed although the target holds a token")
	}
}

func TestManageSecureTokenLaterLeavesTheWrongPasswordStreak(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{"localadmin": true}, token: map[string]bool{}}
	f := &fakeRunner{}
	f.handle = btCoveredHandler(osState, "true", nil, profilesEscrowedYES, nil)
	m := newTestManager(t, f)
	windowPrompt(t, m, f, "correct horse", &fakeWindow{events: []any{dialogEvent{kind: eventLater}}})
	// Set a constant clock so the test does not depend on the current date.
	clock := time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return clock }
	writeState(t, m, fmt.Sprintf(`{"user":"alice","first_prompt":"%s","deferrals":0,"unanswered":0,"wrong_password_runs":3}`, clock.Add(-24*time.Hour).Format(time.RFC3339)))

	var status string
	logged := captureLog(func() { status = m.ManageSecureToken(context.Background(), "localadmin", "newpass", map[string]string{}) })

	if status != TokenStatusDisabledCovered {
		t.Fatalf("status = %q, want %q: a postponed prompt is not a wrong password", status, TokenStatusDisabledCovered)
	}
	if strings.Contains(logged, "[WRONG PASSWORD STREAK]") {
		t.Errorf("a postponed prompt must not log the streak line: %s", logged)
	}
	if st := readState(t, m); st.WrongPasswordRuns != 3 || st.Deferrals != 1 {
		t.Errorf("state = %+v, want streak 3 and one postponement", st)
	}
}

func TestHelperVerifyActionReportsStructuredExitCodes(t *testing.T) {
	raw, err := os.ReadFile("mac_helper.swift")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	if strings.Contains(src, "verifyPasswordNative(user: payload.targetUser, pass: payload.targetPass) ? 0 : 1") {
		t.Error("verify_password exits 1 for a wrong password, a lock and an OpenDirectory error alike")
	}
	for _, required := range []string{
		"func verifyPasswordNative(user: String, pass: String) -> ChangeOutcome",
		"exit(verifyPasswordNative(user: payload.targetUser, pass: payload.targetPass).rawValue)",
		"guard let record else {\n        fputs(\"[SWIFT] User \\(user) not found in OpenDirectory\\n\", stderr)\n        return .odError\n    }",
		"case odErrorInvalidCredentials: outcome = .authFailed",
		"case odErrorAccountLocked, odErrorAccountTemporarilyLocked: outcome = .locked",
		"default: outcome = .odError",
		"case odErrorAccountLocked, odErrorAccountTemporarilyLocked: outcome = .locked\n            case odErrorPolicyViolations: outcome = .policyRejected",
	} {
		if !strings.Contains(src, required) {
			t.Errorf("mac_helper.swift does not contain %s", required)
		}
	}
	if strings.Count(src, "case odErrorAccountLocked:") != 0 {
		t.Error("a switch on the OpenDirectory code maps 5305 without 5304")
	}
}
