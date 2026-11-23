// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

//go:build darwin

package osmgmt

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

const accountPolicyWithFailures = `dsAttrTypeNative:accountPolicyData:
 <?xml version="1.0" encoding="UTF-8"?>
 <plist version="1.0">
 <dict>
 	<key>creationTime</key>
 	<real>1792134681.8886361</real>
 	<key>failedLoginCount</key>
 	<integer>%d</integer>
 	<key>failedLoginTimestamp</key>
 	<real>1792134808.9796062</real>
 	<key>passwordLastSetTime</key>
 	<real>1792134721.694742</real>
 </dict>
 </plist>`

const nativeLAPSLogExcerpt = `2026-10-16 11:13:27.123 Df kandji-library-manager[779:a2e4] [io.kandji.library-manager:LAPS] [LAPS] schedule for 5c661bee-0a15-486f-97c6-f4a688c2bc43: next_rotation_at = null
2026-10-16 11:13:27.124 Df kandji-library-manager[779:a2e4] [io.kandji.library-manager:LAPS] [LAPS] test GoLAPS: rotating 1 account (trigger: checkIn)
2026-10-16 11:13:28.400 Df kandji-library-manager[779:a2e4] [io.kandji.library-manager:LAPS] [LAPS] verify [localadmin]: OpenDirectory rejected the password (Error Domain=com.apple.OpenDirectory Code=5000)
2026-10-16 11:25:29.001 Df kandji-library-manager[779:a2e4] [io.kandji.library-manager:LAPS] [LAPS] test GoLAPS: rotating 1 account (trigger: checkIn)`

func preflightOS(t *testing.T, failed int, extra func(c call) ([]byte, error, bool)) *fakeRunner {
	t.Helper()
	f := &fakeRunner{}
	f.handle = func(c call) ([]byte, error) {
		if extra != nil {
			if out, err, ok := extra(c); ok {
				return out, err
			}
		}
		switch {
		case c.is("id", "-u", "localadmin"):
			return []byte("502"), nil
		case c.is("id", "-u", "laps-bridge"):
			return []byte("id: hasBridge: no such user"), fakeExit{1}
		case c.is("pmset", "-g", "batt"):
			return []byte("Now drawing from 'AC Power'\n -InternalBattery-0 (id=42074211)\t100%; charged; 0:00 remaining present: true"), nil
		case c.is("dscl", ".", "-read", "/Users/localadmin", "accountPolicyData"):
			return []byte(fmt.Sprintf(accountPolicyWithFailures, failed)), nil
		case c.name == "dscl" && c.args[1] == "-deletepl":
			return nil, nil
		case c.is("dseditgroup", "-o", "checkmember", "-m", "localadmin", "admin"):
			return []byte("yes localadmin is a member of admin"), nil
		case c.is("pwpolicy", "-u", "localadmin", "authentication-allowed"):
			return []byte("Policy allows user <localadmin> to authenticate"), nil
		}
		t.Fatalf("unexpected command: %s", c)
		return nil, nil
	}
	return f
}

func TestPreflightSkipsRunOnFlatBattery(t *testing.T) {
	for _, tt := range []struct {
		name string
		out  string
		skip bool
	}{
		{name: "macOS 27 on battery at 7%", out: "Now drawing from 'Battery Power'\n -InternalBattery-0 (id=42074211)\t7%; discharging; 0:18 remaining present: true", skip: true},
		{name: "older macOS Discharging at 9%", out: "Now drawing from 'Battery Power'\n -InternalBattery-0\t9%; Discharging; 0:20 remaining", skip: true},
		{name: "on battery at 50%", out: "Now drawing from 'Battery Power'\n -InternalBattery-0 (id=42074211)\t50%; discharging; 3:18 remaining present: true", skip: false},
		{name: "on AC at 5%", out: "Now drawing from 'AC Power'\n -InternalBattery-0\t5%; charging; 2:00 remaining", skip: false},
		{name: "desktop without a battery", out: "Now drawing from 'AC Power'", skip: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := preflightOS(t, 0, func(c call) ([]byte, error, bool) {
				if c.is("pmset", "-g", "batt") {
					return []byte(tt.out), nil, true
				}
				return nil, nil, false
			})
			err := newTestManager(t, f).Preflight(context.Background(), "localadmin", "https://my.1password.com")
			if tt.skip {
				if !errors.Is(err, ErrSkipRun) {
					t.Fatalf("want ErrSkipRun, got %v", err)
				}
				if f.count("dscl") != 0 {
					t.Fatalf("a skipped run must not touch the account: %v", f.calls)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected preflight error: %v", err)
			}
		})
	}
}

func TestPreflightFailsWithNetworkMarkerWhenOnePasswordUnreachable(t *testing.T) {
	f := preflightOS(t, 0, nil)
	m := newTestManager(t, f)
	m.probe = func(context.Context, string) error { return errors.New("dial tcp: i/o timeout") }
	err := m.Preflight(context.Background(), "localadmin", "https://my.1password.com")
	if err == nil || !strings.HasPrefix(err.Error(), "[NETWORK]") {
		t.Fatalf("an unreachable 1Password must fail with the [NETWORK] marker, got: %v", err)
	}
	if f.count("dscl") != 0 {
		t.Fatalf("the account must not be touched when the vault is unreachable: %v", f.calls)
	}
}

func TestPreflightClearsCounterAndReassertsAdmin(t *testing.T) {
	demoted := true
	f := preflightOS(t, 2, func(c call) ([]byte, error, bool) {
		switch {
		case c.is("dseditgroup", "-o", "checkmember", "-m", "localadmin", "admin"):
			if demoted {
				return []byte("no localadmin is NOT a member of admin"), fakeExit{1}, true
			}
			return []byte("yes localadmin is a member of admin"), nil, true
		case c.is("dseditgroup", "-o", "edit", "-a", "localadmin", "-t", "user", "admin"):
			demoted = false
			return nil, nil, true
		}
		return nil, nil, false
	})
	if err := newTestManager(t, f).Preflight(context.Background(), "localadmin", "https://my.1password.com"); err != nil {
		t.Fatalf("preflight failed: %v", err)
	}
	for _, want := range []string{
		"dscl . -deletepl /Users/localadmin accountPolicyData failedLoginCount",
		"dscl . -deletepl /Users/localadmin accountPolicyData failedLoginTimestamp",
		"dseditgroup -o edit -a localadmin -t user admin",
		"pwpolicy -u localadmin authentication-allowed",
	} {
		if f.indexOf(want) < 0 {
			t.Errorf("missing %q in %v", want, f.calls)
		}
	}
	if demoted {
		t.Fatal("the demoted admin was not re-added")
	}
}

func TestPreflightBelowThresholdIsNotAConflict(t *testing.T) {
	f := preflightOS(t, conflictThreshold-1, nil)
	if err := newTestManager(t, f).Preflight(context.Background(), "localadmin", "https://my.1password.com"); err != nil {
		t.Fatalf("a counter below the threshold must not be a conflict: %v", err)
	}
	if f.count("log show") != 0 {
		t.Fatal("the unified log must only be consulted above the threshold")
	}
}

func TestPreflightConflictNamesNativeLAPSItem(t *testing.T) {
	f := preflightOS(t, 34, func(c call) ([]byte, error, bool) {
		if c.name == "log" {
			return []byte(nativeLAPSLogExcerpt), nil, true
		}
		return nil, nil, false
	})
	err := newTestManager(t, f).Preflight(context.Background(), "localadmin", "https://my.1password.com")
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}
	for _, want := range []string{`"test GoLAPS"`, "34 failed authentications", "2 native rotation attempts", "unassign"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("conflict error lacks %q: %v", want, err)
		}
	}
	if f.count("-deletepl") != 0 || f.count("dseditgroup") != 0 || f.count("pwpolicy") != 0 {
		t.Fatalf("a conflict must stop before any write or repair: %v", f.calls)
	}
}

func TestPreflightConflictWithoutNativeLAPSBlamesUnknownProcess(t *testing.T) {
	f := preflightOS(t, 12, func(c call) ([]byte, error, bool) {
		if c.name == "log" {
			return []byte(""), nil, true
		}
		return nil, nil, false
	})
	err := newTestManager(t, f).Preflight(context.Background(), "localadmin", "https://my.1password.com")
	if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "unknown process") {
		t.Fatalf("want an unknown-process conflict, got %v", err)
	}
	if f.count("-deletepl") != 0 {
		t.Fatal("the counter must be preserved as evidence")
	}
}

func TestPreflightRunsSoftRepairsOnChangeRequiredVerdict(t *testing.T) {
	const blocked = "User <localadmin> is not be allowed to authenticate until password is changed: Credential verification failed because account is temporarily locked."
	setpolicyDone, cleared := false, false
	f := preflightOS(t, 0, func(c call) ([]byte, error, bool) {
		switch {
		case c.is("pwpolicy", "-u", "localadmin", "authentication-allowed"):
			if cleared {
				return []byte("Policy allows user <localadmin> to authenticate"), nil, true
			}
			return []byte(blocked), nil, true
		case c.is("pwpolicy", "-u", "localadmin", "-getpolicy"), c.is("pwpolicy", "-getaccountpolicies"),
			c.is("dscl", ".", "-read", "/Users/localadmin", "PasswordPolicyOptions"), c.is("dscl", ".", "-read", "/Users/localadmin", "AuthenticationAuthority"):
			return []byte("evidence"), nil, true
		case c.is("pwpolicy", "-u", "localadmin", "-setpolicy", "newPasswordRequired=0 maxMinutesUntilChangePassword=0"):
			setpolicyDone = true
			return []byte("Setting policy for localadmin"), nil, true
		case c.is("pwpolicy", "-u", "localadmin", "-clearaccountpolicies"):
			if !setpolicyDone {
				t.Fatal("clearaccountpolicies ran before the legacy-policy reset")
			}
			cleared = true
			return []byte("Clearing account policies for user <localadmin>"), nil, true
		}
		return nil, nil, false
	})
	if err := newTestManager(t, f).Preflight(context.Background(), "localadmin", "https://my.1password.com"); err != nil {
		t.Fatalf("preflight must not fail on a repairable verdict: %v", err)
	}
	if !setpolicyDone || !cleared {
		t.Fatalf("soft repairs did not run (setpolicy=%v clear=%v): %v", setpolicyDone, cleared, f.calls)
	}
	if f.indexOf("pwpolicy -u localadmin -getpolicy") > f.indexOf("pwpolicy -u localadmin -setpolicy") {
		t.Fatal("evidence must be collected BEFORE the repair changes it")
	}
}

func TestPreflightSkipsRepairsForMissingAccount(t *testing.T) {
	f := preflightOS(t, 0, func(c call) ([]byte, error, bool) {
		if c.is("id", "-u", "localadmin") {
			return []byte("id: localadmin: no such user"), fakeExit{1}, true
		}
		return nil, nil, false
	})
	if err := newTestManager(t, f).Preflight(context.Background(), "localadmin", "https://my.1password.com"); err != nil {
		t.Fatalf("a missing account is the rotation step's business, not a preflight error: %v", err)
	}
	if f.count("dscl") != 0 || f.count("pwpolicy") != 0 {
		t.Fatalf("repairs ran against an account that does not exist: %v", f.calls)
	}
}

func TestCleanupLegacyAdmin(t *testing.T) {
	for _, tt := range []struct {
		name        string
		hasBridge   bool
		targetToken bool
		deleteFails bool
		wantDelete  bool
	}{
		{name: "retired once the target holds a token", hasBridge: true, targetToken: true, wantDelete: true},
		{name: "kept while the target has no token", hasBridge: true, targetToken: false, wantDelete: false},
		{name: "nothing to do without laps-bridge", hasBridge: false, targetToken: true, wantDelete: false},
		{name: "refused deletion is left for the next run, never forced", hasBridge: true, targetToken: true, deleteFails: true, wantDelete: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			osState := &fakeOS{exists: map[string]bool{"localadmin": true}, token: map[string]bool{"localadmin": tt.targetToken}}
			if tt.hasBridge {
				osState.exists["laps-bridge"] = true
			}
			f := &fakeRunner{}
			f.handle = func(c call) ([]byte, error) {
				if out, err, ok := osState.handleCommon(c); ok {
					return out, err
				}
				if c.is("sysadminctl", "-deleteUser", "laps-bridge") {
					if tt.deleteFails {
						return []byte("User laps-bridge can not be deleted (it's either last admin user or last secure token user neither of which can be deleted)."), fakeExit{255}
					}
					delete(osState.exists, "laps-bridge")
					return nil, nil
				}
				t.Fatalf("unexpected command: %s", c)
				return nil, nil
			}
			newTestManager(t, f).CleanupLegacyAdmin(context.Background(), "localadmin")
			if got := f.count("sysadminctl -deleteUser laps-bridge") == 1; got != tt.wantDelete {
				t.Fatalf("deleteUser laps-bridge issued=%v, want %v: %v", got, tt.wantDelete, f.calls)
			}
			if f.count("dscl . -delete") != 0 {
				t.Fatalf("laps-bridge must never be force-deleted through dscl: %v", f.calls)
			}
		})
	}
}

func TestCleanupLegacyAdminReportsAbsentOnlyWhenKnown(t *testing.T) {
	for _, tt := range []struct {
		name          string
		hasBridge     bool
		postCheckErr  bool
		wantAbsent    bool
		wantDeleteCmd bool
	}{
		{name: "already gone counts as absent", hasBridge: false, wantAbsent: true},
		{name: "removed in this run is absent", hasBridge: true, wantAbsent: true, wantDeleteCmd: true},
		{name: "a failed check after the deletion is not absent", hasBridge: true, postCheckErr: true, wantAbsent: false, wantDeleteCmd: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			osState := &fakeOS{exists: map[string]bool{"localadmin": true}, token: map[string]bool{"localadmin": true}}
			if tt.hasBridge {
				osState.exists["laps-bridge"] = true
			}
			deleted := false
			f := &fakeRunner{}
			f.handle = func(c call) ([]byte, error) {
				if deleted && tt.postCheckErr && c.is("id", "-u", "laps-bridge") {
					return nil, errors.New("opendirectoryd did not answer")
				}
				if out, err, ok := osState.handleCommon(c); ok {
					return out, err
				}
				if c.is("sysadminctl", "-deleteUser", "laps-bridge") {
					deleted = true
					delete(osState.exists, "laps-bridge")
					return nil, nil
				}
				t.Fatalf("unexpected command: %s", c)
				return nil, nil
			}
			got := newTestManager(t, f).CleanupLegacyAdmin(context.Background(), "localadmin")
			if got != tt.wantAbsent {
				t.Fatalf("absent=%v, want %v: %v", got, tt.wantAbsent, f.calls)
			}
			if issued := f.count("sysadminctl -deleteUser laps-bridge") == 1; issued != tt.wantDeleteCmd {
				t.Fatalf("deleteUser issued=%v, want %v: %v", issued, tt.wantDeleteCmd, f.calls)
			}
		})
	}
}

func bridgeCounterOS(t *testing.T, bridgeFailed int) *fakeRunner {
	t.Helper()
	return preflightOS(t, 0, func(c call) ([]byte, error, bool) {
		switch {
		case c.is("id", "-u", "laps-bridge"):
			return []byte("503"), nil, true
		case c.is("dscl", ".", "-read", "/Users/laps-bridge", "accountPolicyData"):
			return []byte(fmt.Sprintf(accountPolicyWithFailures, bridgeFailed)), nil, true
		}
		return nil, nil, false
	})
}

func TestPreflightKeepsBridgeCounterAtThreshold(t *testing.T) {
	f := bridgeCounterOS(t, conflictThreshold)

	var err error
	logged := captureLog(func() {
		err = newTestManager(t, f).Preflight(context.Background(), "localadmin", "https://my.1password.com")
	})

	if err != nil {
		t.Fatalf("a laps-bridge counter at the threshold must not stop the run: %v", err)
	}
	if n := f.count("dscl . -deletepl /Users/laps-bridge"); n != 0 {
		t.Fatalf("the laps-bridge counter was cleared %d time(s); it is evidence and must stay: %v", n, f.calls)
	}
	want := fmt.Sprintf("[CONFLICT] laps-bridge has %d recorded failed logins since the last run; the counter is kept as evidence and not cleared", conflictThreshold)
	if !strings.Contains(logged, want) {
		t.Fatalf("missing %q in the log:\n%s", want, logged)
	}
}

func TestPreflightClearsBridgeCounterBelowThreshold(t *testing.T) {
	f := bridgeCounterOS(t, conflictThreshold-1)

	var err error
	logged := captureLog(func() {
		err = newTestManager(t, f).Preflight(context.Background(), "localadmin", "https://my.1password.com")
	})

	if err != nil {
		t.Fatalf("preflight failed: %v", err)
	}
	for _, want := range []string{
		"dscl . -deletepl /Users/laps-bridge accountPolicyData failedLoginCount",
		"dscl . -deletepl /Users/laps-bridge accountPolicyData failedLoginTimestamp",
	} {
		if f.indexOf(want) < 0 {
			t.Errorf("missing %q in %v", want, f.calls)
		}
	}
	if strings.Contains(logged, "[CONFLICT] laps-bridge") {
		t.Fatalf("a counter below the threshold is not a conflict:\n%s", logged)
	}
}

func TestPreflightRefusesUntrustedHelperOrWindow(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
	}{
		{name: "helper owned by a user", path: helperPath},
		{name: "window owned by a user", path: authWindowPath},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := preflightOS(t, 0, nil)
			m := newTestManager(t, f)
			tree := rootOwnedTree(helperPath)
			for dir, info := range rootOwnedTree(authWindowPath) {
				tree[dir] = info
			}
			tree[tc.path] = fakeFileInfo{name: filepath.Base(tc.path), mode: 0o755, uid: 501}
			m.lstat = fakeTree(tree)

			err := m.Preflight(context.Background(), "localadmin", "https://my.1password.com")
			if err == nil {
				t.Fatal("an untrusted binary must fail the preflight")
			}
			if !strings.Contains(err.Error(), tc.path) || !strings.Contains(err.Error(), "uid 501") {
				t.Fatalf("the error must name the path and the reason, got: %v", err)
			}
			if errors.Is(err, ErrSkipRun) {
				t.Fatalf("an untrusted binary is an error, not a skip: %v", err)
			}
			for _, tool := range []string{"id", "dscl", "dseditgroup", "pwpolicy"} {
				if f.count(tool) != 0 {
					t.Fatalf("%s ran after the failed trust check: %v", tool, f.calls)
				}
			}
		})
	}
}

func TestPreflightProceedsWithTrustedBinaries(t *testing.T) {
	f := preflightOS(t, 0, nil)
	m := newTestManager(t, f)
	m.lstat = rootOwnedLstat
	if err := m.Preflight(context.Background(), "localadmin", "https://my.1password.com"); err != nil {
		t.Fatalf("preflight failed with a trusted chain: %v", err)
	}
	if f.count("dscl") == 0 {
		t.Fatalf("the account checks did not run: %v", f.calls)
	}
}
