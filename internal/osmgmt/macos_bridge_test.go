// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

//go:build darwin

package osmgmt

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strings"
	"sync"
	"testing"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func captureLog(fn func()) string {
	var buf syncBuffer
	prev := log.Writer()
	log.SetOutput(&buf)
	fn()
	log.SetOutput(prev)
	return buf.String()
}

func grantOS(t *testing.T, osState *fakeOS) *fakeRunner {
	t.Helper()
	f := &fakeRunner{}
	f.handle = func(c call) ([]byte, error) {
		if out, err, ok := osState.handleCommon(c); ok {
			return out, err
		}
		switch {
		case c.is("dscl", ".", "-list", "/Users", "UniqueID"):
			var b strings.Builder
			uid := 501
			for user := range osState.exists {
				b.WriteString(user + "  " + itoa(uid) + "\n")
				uid++
			}
			return []byte(b.String()), nil
		case c.name == "mac_helper":
			p := decodePayload(t, c)
			if p.Action == "grant_token" {
				osState.token[p.TargetUser] = true
				return []byte("[SWIFT] Token granted securely via stdin."), nil
			}
			return nil, fakeExit{1}
		case c.is("fdesetup", "haspersonalrecoverykey"):
			return []byte("false"), nil
		case c.name == "profiles":
			return []byte("Bootstrap Token escrowed to server: NO"), nil
		}
		t.Fatalf("unexpected command: %s", c)
		return nil, nil
	}
	return f
}

func itoa(n int) string {
	return string(rune('0'+n/100)) + string(rune('0'+(n/10)%10)) + string(rune('0'+n%10))
}

func grantPayloads(t *testing.T, f *fakeRunner) []SwiftPayload {
	t.Helper()
	var out []SwiftPayload
	for _, c := range f.calls {
		if c.name == "mac_helper" {
			if p := decodePayload(t, c); p.Action == "grant_token" {
				out = append(out, p)
			}
		}
	}
	return out
}

func TestManageSecureTokenSkipsBridgeCandidate(t *testing.T) {
	osState := &fakeOS{
		exists:   map[string]bool{"localadmin": true, "laps-bridge": true, "jdoe": true},
		token:    map[string]bool{"laps-bridge": true, "jdoe": true},
		realName: map[string]string{"laps-bridge": bridgeFullName},
		blocked:  map[string]bool{},
	}
	f := grantOS(t, osState)
	m := newTestManager(t, f)
	prompted := false
	m.prompt = func(context.Context, string, string) promptResult {
		prompted = true
		return promptResult{outcome: passwordUnavailable}
	}

	m.ManageSecureToken(context.Background(), "localadmin", "new-pass", map[string]string{"MDM_FALLBACK_PASS": "legacy"})

	if n := len(grantPayloads(t, f)); n != 0 {
		t.Fatalf("the bridge received %d silent grant attempt(s); its password is random and unsaved, every attempt only feeds its failed-login counter", n)
	}
	if !prompted {
		t.Fatal("the GUI prompt must still run: the console user holds a token")
	}
}

func TestManageSecureTokenTriesLegacyBridgeOnce(t *testing.T) {
	for _, tt := range []struct {
		name   string
		creds  map[string]string
		pass   string
		status string
	}{
		{name: "MDM fallback", creds: map[string]string{"MDM_FALLBACK_PASS": "legacy"}, pass: "legacy", status: "ENABLED (Silent - MDM)"},
		{name: "vault password wins", creds: map[string]string{"laps-bridge": "from-vault", "MDM_FALLBACK_PASS": "legacy"}, pass: "from-vault", status: "ENABLED (Silent - Vault)"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			osState := &fakeOS{
				exists:  map[string]bool{"localadmin": true, "laps-bridge": true},
				token:   map[string]bool{"laps-bridge": true},
				blocked: map[string]bool{},
			}
			f := grantOS(t, osState)
			m := newTestManager(t, f)

			status := m.ManageSecureToken(context.Background(), "localadmin", "new-pass", tt.creds)

			got := grantPayloads(t, f)
			if len(got) != 1 || got[0].AdminUser != "laps-bridge" || got[0].AdminPass != tt.pass {
				t.Fatalf("want exactly one grant attempt through laps-bridge with the %s password, got %+v", tt.name, got)
			}
			if status != tt.status {
				t.Fatalf("status = %q, want %q", status, tt.status)
			}
		})
	}
}

func TestManageSecureTokenUsesEscrowedBridgePassword(t *testing.T) {
	osState := &fakeOS{
		exists:   map[string]bool{"localadmin": true, "laps-bridge": true},
		token:    map[string]bool{"laps-bridge": true},
		realName: map[string]string{"laps-bridge": bridgeFullName},
		blocked:  map[string]bool{},
	}
	f := grantOS(t, osState)
	m := newTestManager(t, f)

	status := m.ManageSecureToken(context.Background(), "localadmin", "new-pass", map[string]string{"laps-bridge": "escrowed", "MDM_FALLBACK_PASS": "legacy"})

	got := grantPayloads(t, f)
	if len(got) != 1 || got[0].AdminPass != "escrowed" {
		t.Fatalf("want one attempt with the escrowed bridge password, got %+v", got)
	}
	if status != "ENABLED (Silent - Vault)" {
		t.Fatalf("status = %q", status)
	}
}

func TestManageSecureTokenSkipsUnusableCandidate(t *testing.T) {
	for _, tt := range []struct {
		name     string
		blocked  bool
		failed   int
		attempts int
	}{
		{name: "pwpolicy blocks the candidate", blocked: true, attempts: 0},
		{name: "counter at the threshold", failed: conflictThreshold, attempts: 0},
		{name: "counter below the threshold", failed: conflictThreshold - 1, attempts: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			osState := &fakeOS{
				exists:  map[string]bool{"localadmin": true, "laps-bridge": true},
				token:   map[string]bool{"laps-bridge": true},
				blocked: map[string]bool{"laps-bridge": tt.blocked},
				failed:  map[string]int{"laps-bridge": tt.failed},
			}
			f := grantOS(t, osState)
			m := newTestManager(t, f)

			m.ManageSecureToken(context.Background(), "localadmin", "new-pass", map[string]string{"MDM_FALLBACK_PASS": "legacy"})

			if n := len(grantPayloads(t, f)); n != tt.attempts {
				t.Fatalf("got %d grant attempt(s), want %d", n, tt.attempts)
			}
		})
	}
}

func TestManageSecureTokenReportsDeadlock(t *testing.T) {
	osState := &fakeOS{
		exists:   map[string]bool{"localadmin": true, "laps-bridge": true, "jdoe": true},
		token:    map[string]bool{"laps-bridge": true},
		realName: map[string]string{"laps-bridge": bridgeFullName},
		blocked:  map[string]bool{},
	}
	f := grantOS(t, osState)
	m := newTestManager(t, f)

	var status string
	logged := captureLog(func() {
		status = m.ManageSecureToken(context.Background(), "localadmin", "new-pass", map[string]string{"MDM_FALLBACK_PASS": "legacy"})
	})

	if status != TokenStatusDisabledDeadlock {
		t.Fatalf("status = %q, want %q", status, TokenStatusDisabledDeadlock)
	}
	if status == TokenStatusDisabledCovered {
		t.Fatal("a deadlock must never report as covered")
	}
	if !strings.Contains(logged, "[DEADLOCK]") || !strings.Contains(logged, "login window") {
		t.Fatalf("the deadlock line must name the login-window remedy; log:\n%s", logged)
	}
	if !strings.Contains(logged, "BRIDGE: bridge=bridge token=yes password=unknown verdict=deadlock") {
		t.Fatalf("missing or wrong BRIDGE: report line; log:\n%s", logged)
	}
}

func TestManageSecureTokenBridgeReportOnCleanMac(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{"localadmin": true}, token: map[string]bool{"localadmin": true}}
	f := grantOS(t, osState)
	m := newTestManager(t, f)

	logged := captureLog(func() { m.ManageSecureToken(context.Background(), "localadmin", "new-pass", nil) })

	if !strings.Contains(logged, "BRIDGE: bridge=absent token=no password=unknown verdict=ok") {
		t.Fatalf("wrong BRIDGE: line; log:\n%s", logged)
	}
}

func TestWithBridgeAdminRefusesWithoutTokenHolder(t *testing.T) {
	for _, tt := range []struct {
		name        string
		diskutilErr bool
	}{
		{name: "diskutil lists no local OD user"},
		{name: "diskutil fails and the scan finds nobody", diskutilErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			osState := &fakeOS{exists: map[string]bool{"localadmin": true, "jdoe": true}, token: map[string]bool{}}
			f := &fakeRunner{}
			f.handle = func(c call) ([]byte, error) {
				if tt.diskutilErr && c.name == "diskutil" {
					return []byte("Could not find disk"), fakeExit{1}
				}
				if out, err, ok := osState.handleCommon(c); ok {
					return out, err
				}
				switch {
				case c.is("sysadminctl", "-deleteUser", "localadmin"):
					return []byte("Unable to delete the last admin user"), fakeExit{1}
				case c.is("dscl", ".", "-list", "/Users", "UniqueID"):
					return []byte("localadmin  501\njdoe  502\n"), nil
				}
				t.Fatalf("unexpected command: %s", c)
				return nil, nil
			}
			m := newTestManager(t, f)

			var err error
			logged := captureLog(func() { err = m.healAccount(context.Background(), "localadmin", "NewPass-1") })

			if !errors.Is(err, ErrNoTokenHolder) {
				t.Fatalf("want ErrNoTokenHolder, got %v", err)
			}
			if errors.Is(err, ErrSkipRun) {
				t.Fatal("the refusal must fail the run red, not skip it")
			}
			if f.count("sysadminctl -addUser") != 0 {
				t.Fatalf("no account may be created on a Mac without a token holder: %v", f.calls)
			}
			if !osState.exists["localadmin"] {
				t.Fatal("the target must stay")
			}
			if !strings.Contains(logged, "[NO TOKEN HOLDER]") || !strings.Contains(logged, "verdict=no-token-holder") {
				t.Fatalf("missing log lines:\n%s", logged)
			}
		})
	}
}

func TestWithBridgeAdminEscrowsBeforeCreate(t *testing.T) {
	newLadder := func(t *testing.T) (*fakeRunner, *fakeOS) {
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
		return f, osState
	}

	t.Run("escrow precedes creation and carries the password", func(t *testing.T) {
		f, _ := newLadder(t)
		m := newTestManager(t, f)
		var escrowed string
		var createdBefore bool
		m.escrowBridge = func(_ context.Context, pass string) error {
			escrowed = pass
			createdBefore = f.count("sysadminctl -addUser laps-bridge") > 0
			return nil
		}
		if err := m.healAccount(context.Background(), "localadmin", "NewPass-1"); err != nil {
			t.Fatalf("heal failed: %v", err)
		}
		if escrowed == "" || createdBefore {
			t.Fatalf("escrow must run before -addUser with the bridge password (escrowed=%v, createdBefore=%v)", escrowed != "", createdBefore)
		}
		i := f.indexOf("sysadminctl -addUser laps-bridge")
		if i < 0 || f.calls[i].stdin != escrowed+"\n" {
			t.Fatal("the bridge must be created with the escrowed password")
		}
	})

	t.Run("escrow failure means no bridge", func(t *testing.T) {
		f, osState := newLadder(t)
		m := newTestManager(t, f)
		m.escrowBridge = func(context.Context, string) error { return errors.New("vault write timed out") }
		err := m.healAccount(context.Background(), "localadmin", "NewPass-1")
		if err == nil || !strings.Contains(err.Error(), "escrow") {
			t.Fatalf("want an escrow error, got %v", err)
		}
		if f.count("sysadminctl -addUser laps-bridge") != 0 || !osState.exists["localadmin"] {
			t.Fatalf("no bridge may exist after a failed escrow: %v", f.calls)
		}
	})

	t.Run("no escrow route means no bridge", func(t *testing.T) {
		f, _ := newLadder(t)
		m := newTestManager(t, f)
		m.escrowBridge = nil
		if err := m.healAccount(context.Background(), "localadmin", "NewPass-1"); err == nil {
			t.Fatal("want an error without an escrow route")
		}
		if f.count("sysadminctl -addUser laps-bridge") != 0 {
			t.Fatal("no bridge may be created without an escrow route")
		}
	})
}

func TestPreflightKeepsBridgeCounterWithoutAbort(t *testing.T) {
	f := preflightOS(t, 0, func(c call) ([]byte, error, bool) {
		switch {
		case c.is("id", "-u", "laps-bridge"):
			return []byte("503"), nil, true
		case c.is("dscl", ".", "-read", "/Users/laps-bridge", "accountPolicyData"):
			return []byte("dsAttrTypeNative:accountPolicyData:\n <plist><dict><key>failedLoginCount</key><integer>34</integer></dict></plist>"), nil, true
		}
		return nil, nil, false
	})
	m := newTestManager(t, f)

	var err error
	logged := captureLog(func() { err = m.Preflight(context.Background(), "localadmin", "https://my.1password.com") })

	if err != nil {
		t.Fatalf("a laps-bridge counter must never abort the run: %v", err)
	}
	if f.count("dscl . -deletepl /Users/laps-bridge accountPolicyData") != 0 {
		t.Fatalf("a laps-bridge counter at the threshold is evidence and must stay: %v", f.calls)
	}
	if !strings.Contains(logged, "[CONFLICT] laps-bridge has 34 recorded failed logins since the last run") {
		t.Fatalf("the count must stay in the log as evidence:\n%s", logged)
	}
	if strings.Contains(logged, "[ERROR]") {
		t.Fatalf("laps-bridge must never fail the run:\n%s", logged)
	}
}

func TestCountLocalCryptoUsers(t *testing.T) {
	const withHolder = `Cryptographic users for disk3s1 (4 found)
|
+-- 3A1C7B7E-0000-4C1E-9B5B-1234567890AB
|   Type: Local Open Directory User
|
+-- EBC6C064-0000-11AA-AA11-00306543ECAC
|   Type: Personal Recovery User
|
+-- 2457C9D8-0000-11AA-AA11-00306543ECAC
|   Type: MDM Bootstrap Token External Key
|
+-- 64C0C6EB-0000-11AA-AA11-00306543ECAC
    Type: Unknown
`
	const zeroHolder = `Cryptographic users for disk3s1 (2 found)
|
+-- EBC6C064-0000-11AA-AA11-00306543ECAC
|   Type: Personal Recovery User
|
+-- 2457C9D8-0000-11AA-AA11-00306543ECAC
    Type: MDM Bootstrap Token External Key
`
	for _, tt := range []struct {
		name string
		out  string
		want int
	}{
		{name: "one local user", out: withHolder, want: 1},
		{name: "only PRK and bootstrap token", out: zeroHolder, want: 0},
		{name: "not a listing", out: "Could not find disk: /", want: -1},
		{name: "empty", out: "", want: -1},
	} {
		if got := countLocalCryptoUsers(tt.out); got != tt.want {
			t.Errorf("%s: countLocalCryptoUsers = %d, want %d", tt.name, got, tt.want)
		}
	}
}

func TestGetTokenHoldersHasNoLiteralFallback(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{"localadmin": true, "jdoe": true, "laps-bridge": true}, token: map[string]bool{}}
	f := &fakeRunner{}
	f.handle = func(c call) ([]byte, error) {
		if out, err, ok := osState.handleCommon(c); ok {
			return out, err
		}
		if c.is("dscl", ".", "-list", "/Users", "UniqueID") {
			return []byte("localadmin  501\njdoe  502\nlaps-bridge  503\n"), nil
		}
		t.Fatalf("unexpected command: %s", c)
		return nil, nil
	}
	if got := newTestManager(t, f).getTokenHolders(context.Background()); len(got) != 0 {
		t.Fatalf("want no holders, got %v", got)
	}
}

func TestCleanupRemovesTokenlessBridgeWithoutTargetToken(t *testing.T) {
	for _, tt := range []struct {
		name        string
		realName    string
		bridgeToken bool
		notAdmin    bool
		removed     bool
	}{
		{name: "token-less LAPS bridge goes", realName: bridgeFullName, removed: true},
		{name: "bridge stays while the target is not an admin", realName: bridgeFullName, notAdmin: true, removed: false},
		{name: "legacy laps-bridge stays", realName: "laps-bridge", removed: false},
		{name: "bridge with a token stays", realName: bridgeFullName, bridgeToken: true, removed: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			osState := &fakeOS{
				exists:   map[string]bool{"localadmin": true, "laps-bridge": true},
				token:    map[string]bool{"laps-bridge": tt.bridgeToken},
				realName: map[string]string{"laps-bridge": tt.realName},
			}
			f := &fakeRunner{}
			f.handle = func(c call) ([]byte, error) {
				if out, err, ok := osState.handleCommon(c); ok {
					return out, err
				}
				switch {
				case c.is("dseditgroup", "-o", "checkmember", "-m", "localadmin", "admin"):
					if tt.notAdmin {
						return []byte("no localadmin is NOT a member of admin"), fakeExit{67}
					}
					return []byte("yes localadmin is a member of admin"), nil
				case c.is("sysadminctl", "-deleteUser", "laps-bridge"):
					delete(osState.exists, "laps-bridge")
					return nil, nil
				}
				t.Fatalf("unexpected command: %s", c)
				return nil, nil
			}
			got := newTestManager(t, f).CleanupLegacyAdmin(context.Background(), "localadmin")
			if got != tt.removed || osState.exists["laps-bridge"] == tt.removed {
				t.Fatalf("removed=%v (want %v), laps-bridge exists=%v", got, tt.removed, osState.exists["laps-bridge"])
			}
		})
	}
}
