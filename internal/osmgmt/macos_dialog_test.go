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
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type fakeWindow struct {
	events     []any
	wrongs     []int
	closed     int
	neverShown bool
	shownSent  bool
	wrongErr   error
	views      []string
	showErr    error
	pauses     []int
	pauseErr   error
}

func (w *fakeWindow) pause(seconds int) error {
	w.pauses = append(w.pauses, seconds)
	return w.pauseErr
}

func (w *fakeWindow) show(view string) error {
	w.views = append(w.views, view)
	return w.showErr
}

func (w *fakeWindow) next(ctx context.Context) (dialogEvent, error) {
	if !w.neverShown && !w.shownSent {
		w.shownSent = true
		return dialogEvent{kind: eventShown}, nil
	}
	if len(w.events) == 0 {
		return dialogEvent{}, io.EOF
	}
	e := w.events[0]
	w.events = w.events[1:]
	switch v := e.(type) {
	case error:
		return dialogEvent{}, v
	case func() (dialogEvent, error):
		return v()
	case func(context.Context) (dialogEvent, error):
		return v(ctx)
	}
	return e.(dialogEvent), nil
}

func (w *fakeWindow) wrong(attempt int) error {
	w.wrongs = append(w.wrongs, attempt)
	return w.wrongErr
}

func (w *fakeWindow) close() { w.closed++ }

const ioregUnlocked = `<key>IOConsoleUsers</key><array><dict><key>kCGSSessionOnConsoleKey</key><true/><key>kCGSSessionUserNameKey</key><string>alice</string></dict></array>`
const ioregLocked = `<key>IOConsoleUsers</key><array><dict><key>CGSSessionScreenIsLocked</key>
			<true/><key>kCGSSessionOnConsoleKey</key><true/><key>kCGSSessionUserNameKey</key><string>alice</string></dict></array>`

func ask(m *MacOSManager, ctx context.Context, needAdmin bool) (string, passwordOutcome) {
	var got string
	outcome, _ := m.askPassword(ctx, "501", "alice", needAdmin, func(_ context.Context, password string) error {
		got = password
		return nil
	})
	return got, outcome
}

func typed(pass string) dialogEvent { return dialogEvent{kind: eventPassword, password: pass} }

func dialogManager(t *testing.T, win *fakeWindow, openErr error, correct string) (*MacOSManager, *fakeRunner, *[]dialogRequest) {
	t.Helper()
	f := &fakeRunner{}
	f.handle = func(c call) ([]byte, error) {
		if c.name == "ioreg" {
			return []byte(ioregUnlocked), nil
		}
		if c.is("dseditgroup", "-o", "checkmember", "-m", "alice", "admin") {
			return []byte("yes alice is a member of admin"), nil
		}
		if c.name != "mac_helper" {
			t.Fatalf("unexpected command: %s", c)
		}
		p := decodePayload(t, c)
		if p.Action != "verify_password" {
			t.Fatalf("unexpected helper action %q", p.Action)
		}
		if p.TargetUser == "alice" && p.TargetPass == correct {
			return nil, nil
		}
		return nil, fakeExit{1}
	}
	m := newTestManager(t, f)
	m.promptStatePath = filepath.Join(t.TempDir(), "golaps", "token_prompt.json")
	var requests []dialogRequest
	m.openWindow = func(_ context.Context, _, _ string, req dialogRequest) (passwordWindow, error) {
		requests = append(requests, req)
		if openErr != nil {
			return nil, openErr
		}
		return win, nil
	}
	m.openApp = func(context.Context, string, string, string) error { return nil }
	return m, f, &requests
}

func TestAskPasswordReturnsVerifiedPassword(t *testing.T) {
	win := &fakeWindow{events: []any{typed("correct horse")}}
	m, f, requests := dialogManager(t, win, nil, "correct horse")

	pass, outcome := ask(m, context.Background(), false)

	if outcome != passwordOK || pass != "correct horse" {
		t.Fatalf("got (%q, %v), want the verified password and passwordOK", pass, outcome)
	}
	if n := f.count("mac_helper"); n != 1 {
		t.Errorf("helper ran %d time(s), want exactly one verification", n)
	}
	if len(win.wrongs) != 0 {
		t.Errorf("a correct password must not report a wrong attempt (%v)", win.wrongs)
	}
	if !reflect.DeepEqual(win.views, []string{viewWorking, viewDone}) {
		t.Errorf("views = %v, want the progress view and then the success view in the same window", win.views)
	}
	if win.closed == 0 {
		t.Error("the window stayed open after the password was accepted")
	}
	want := dialogRequest{Attempt: 1, MaxAttempts: maxPasswordAttempts, DeferralsLeft: maxDeferrals, TimeoutSeconds: int(dialogWait / time.Second)}
	if len(*requests) != 1 || (*requests)[0] != want {
		t.Errorf("window request = %+v, want %+v", *requests, want)
	}
}

func TestAskPasswordReportsWrongPasswordToTheWindow(t *testing.T) {
	win := &fakeWindow{events: []any{typed("typo"), typed("correct horse")}}
	m, f, _ := dialogManager(t, win, nil, "correct horse")

	pass, outcome := ask(m, context.Background(), false)

	if outcome != passwordOK || pass != "correct horse" {
		t.Fatalf("got (%q, %v), want the second password and passwordOK", pass, outcome)
	}
	if !reflect.DeepEqual(win.wrongs, []int{2}) {
		t.Errorf("window was told about attempts %v, want [2]: the window keeps no count of its own", win.wrongs)
	}
	if n := f.count("mac_helper"); n != 2 {
		t.Errorf("helper ran %d time(s), want one verification per typed password", n)
	}
}

func TestAskPasswordStopsAfterMaxAttempts(t *testing.T) {
	var events []any
	for i := 0; i < maxPasswordAttempts+3; i++ {
		events = append(events, typed("wrong"))
	}
	win := &fakeWindow{events: events}
	m, f, _ := dialogManager(t, win, nil, "correct horse")

	pass, outcome := ask(m, context.Background(), false)

	if outcome != passwordFailed || pass != "" {
		t.Fatalf("got (%q, %v), want passwordFailed without a password", pass, outcome)
	}
	if n := f.count("mac_helper"); n != maxPasswordAttempts {
		t.Errorf("helper ran %d time(s), want %d: each one costs the user a failed login", n, maxPasswordAttempts)
	}
	if !reflect.DeepEqual(win.wrongs, []int{2, 3, 4, 5}) {
		t.Errorf("window was told about attempts %v, want [2 3 4 5]", win.wrongs)
	}
	if !reflect.DeepEqual(win.views, []string{viewFailed}) {
		t.Errorf("views = %v, want the view that sends the user to the IT team", win.views)
	}
	if win.closed == 0 {
		t.Error("the window stayed open after the last attempt")
	}
}

func TestAskPasswordLaterEndsWithoutVerification(t *testing.T) {
	win := &fakeWindow{events: []any{dialogEvent{kind: eventLater}}}
	m, f, _ := dialogManager(t, win, nil, "correct horse")
	var pass string
	var outcome passwordOutcome
	logged := captureLog(func() { pass, outcome = ask(m, context.Background(), false) })

	if outcome != passwordLater || pass != "" {
		t.Fatalf("got (%q, %v), want passwordLater without a password", pass, outcome)
	}
	if n := f.count("mac_helper"); n != 0 {
		t.Errorf("helper ran %d time(s) for a user who typed nothing", n)
	}
	if !strings.Contains(logged, "[DEFERRED 1/3] alice postponed the Secure Token grant") {
		t.Errorf("the fleet report greps the [DEFERRED] line; log was: %s", logged)
	}
	if win.closed == 0 {
		t.Error("the window stayed open after Later")
	}
}

func TestAskPasswordWindowTimeoutIsNotAFailure(t *testing.T) {
	win := &fakeWindow{events: []any{dialogEvent{kind: eventTimeout}}}
	m, _, _ := dialogManager(t, win, nil, "correct horse")
	var outcome passwordOutcome
	logged := captureLog(func() { _, outcome = ask(m, context.Background(), false) })

	if outcome != passwordTimeout {
		t.Fatalf("got %v, want passwordTimeout: an absent user did not forget the password", outcome)
	}
	if strings.Contains(logged, "signal: killed") {
		t.Errorf("a window that closed itself must not be logged as a killed process: %s", logged)
	}
}

func TestAskPasswordExpiredBudgetIsATimeoutNotAFallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	win := &fakeWindow{events: []any{context.Canceled}}
	m, _, requests := dialogManager(t, win, nil, "correct horse")

	_, outcome := ask(m, ctx, false)

	if outcome != passwordTimeout {
		t.Fatalf("got %v, want passwordTimeout", outcome)
	}
	if len(*requests) != 0 {
		t.Errorf("no window may open when the run budget is gone (windows: %d)", len(*requests))
	}
	if _, err := os.Stat(m.promptStatePath); !os.IsNotExist(err) {
		t.Error("a prompt that never opened wrote a deferral record")
	}
}

var promptDay = time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)

func writeState(t *testing.T, m *MacOSManager, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(m.promptStatePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.promptStatePath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readState(t *testing.T, m *MacOSManager) promptState {
	t.Helper()
	raw, err := os.ReadFile(m.promptStatePath)
	if err != nil {
		t.Fatalf("no prompt state on disk: %v", err)
	}
	var file struct {
		Records map[string]promptState `json:"records"`
		promptState
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("prompt state is not JSON: %v | %s", err, raw)
	}
	if file.Records == nil {
		return file.promptState
	}
	st, ok := file.Records["alice"]
	if !ok {
		t.Fatalf("the prompt state has no record of alice: %s", raw)
	}
	return st
}

func TestPromptStateKeepsARecordForEachUser(t *testing.T) {
	win := &fakeWindow{events: []any{dialogEvent{kind: eventTimeout}}}
	m, _, requests := dialogManager(t, win, nil, "correct horse")
	m.now = func() time.Time { return promptDay }
	writeState(t, m, `{"user":"bob","first_prompt":"2026-11-16T09:00:00Z","deferrals":2,"unanswered":3,"wrong_password_runs":1,"window_failed_runs":1}`)

	ask(m, context.Background(), false)

	if got := (*requests)[0].DeferralsLeft; got != maxDeferrals {
		t.Errorf("alice got %d postponement(s), want a full budget of %d", got, maxDeferrals)
	}
	if alice := readState(t, m); alice.User != "alice" || alice.Unanswered != 1 {
		t.Errorf("record of alice = %+v, want one unanswered prompt", alice)
	}
	bob := m.loadPromptState("bob")
	if bob.Deferrals != 2 || bob.Unanswered != 3 || bob.WrongPasswordRuns != 1 || bob.WindowFailedRuns != 1 {
		t.Errorf("record of bob = %+v, want it unchanged after the prompt of alice", bob)
	}
}

func TestFirstPromptStartsTheDeferralBudget(t *testing.T) {
	win := &fakeWindow{events: []any{dialogEvent{kind: eventTimeout}}}
	m, _, requests := dialogManager(t, win, nil, "correct horse")
	m.now = func() time.Time { return promptDay }

	ask(m, context.Background(), false)

	if got := (*requests)[0].DeferralsLeft; got != maxDeferrals {
		t.Errorf("first prompt offers %d postponement(s), want %d", got, maxDeferrals)
	}
	st := readState(t, m)
	if st.User != "alice" || !st.FirstPrompt.Equal(promptDay) || st.Deferrals != 0 {
		t.Errorf("state = %+v, want alice, first prompt %s, 0 deferrals: a timeout must not consume a postponement", st, promptDay)
	}
	if st.Unanswered != 1 {
		t.Errorf("unanswered = %d, want 1: a timeout is a prompt without a password", st.Unanswered)
	}
	info, err := os.Stat(m.promptStatePath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("state file mode = %v (err %v), want 0600: a user must not be able to refill the budget", info.Mode().Perm(), err)
	}
}

func TestLaterConsumesOneDeferral(t *testing.T) {
	win := &fakeWindow{events: []any{dialogEvent{kind: eventLater}}}
	m, _, requests := dialogManager(t, win, nil, "correct horse")
	m.now = func() time.Time { return promptDay }
	writeState(t, m, `{"user":"alice","first_prompt":"2026-11-16T09:00:00Z","deferrals":1}`)

	var outcome passwordOutcome
	logged := captureLog(func() { _, outcome = ask(m, context.Background(), false) })

	if outcome != passwordLater {
		t.Fatalf("got %v, want passwordLater", outcome)
	}
	if got := (*requests)[0].DeferralsLeft; got != 2 {
		t.Errorf("window offered %d postponement(s), want 2", got)
	}
	st := readState(t, m)
	if st.Deferrals != 2 || !st.FirstPrompt.Equal(promptDay.Add(-24*time.Hour)) {
		t.Errorf("state = %+v, want 2 deferrals and the first prompt kept", st)
	}
	if !strings.Contains(logged, "[DEFERRED 2/3] alice postponed the Secure Token grant") {
		t.Errorf("log lacks the [DEFERRED 2/3] line: %s", logged)
	}
}

func TestNoLaterWhenTheBudgetIsSpent(t *testing.T) {
	cases := []struct {
		name  string
		state string
	}{
		{"three postponements", `{"user":"alice","first_prompt":"2026-11-16T09:00:00Z","deferrals":3}`},
		{"seven days after the first prompt", `{"user":"alice","first_prompt":"2026-11-10T08:59:59Z","deferrals":1}`},
		{"more postponements than the limit", `{"user":"alice","first_prompt":"2026-11-16T09:00:00Z","deferrals":5}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			win := &fakeWindow{events: []any{dialogEvent{kind: eventTimeout}}}
			m, _, requests := dialogManager(t, win, nil, "correct horse")
			m.now = func() time.Time { return promptDay }
			writeState(t, m, tc.state)

			logged := captureLog(func() { ask(m, context.Background(), false) })

			if got := (*requests)[0].DeferralsLeft; got != 0 {
				t.Errorf("window offered %d postponement(s), want 0", got)
			}
			if !strings.Contains(logged, "[DEFERRAL LIMIT] alice can no longer postpone the Secure Token grant") {
				t.Errorf("log lacks the [DEFERRAL LIMIT] line that the fleet report needs: %s", logged)
			}
		})
	}
}

func TestLaterWithoutAnOfferIsNotAccepted(t *testing.T) {
	win := &fakeWindow{events: []any{dialogEvent{kind: eventLater}}}
	m, _, _ := dialogManager(t, win, nil, "correct horse")
	m.now = func() time.Time { return promptDay }
	writeState(t, m, `{"user":"alice","first_prompt":"2026-11-16T09:00:00Z","deferrals":3}`)

	var outcome passwordOutcome
	logged := captureLog(func() { _, outcome = ask(m, context.Background(), false) })

	if outcome == passwordLater {
		t.Error("a later answer was accepted although the budget is spent")
	}
	if st := readState(t, m); st.Deferrals != 3 {
		t.Errorf("deferrals = %d, want 3", st.Deferrals)
	}
	if strings.Contains(logged, "[DEFERRED") {
		t.Errorf("a refused later answer was logged as a postponement: %s", logged)
	}
}

func TestPromptStateStartsFreshWhenItCannotBeTrusted(t *testing.T) {
	cases := []struct {
		name  string
		state string
	}{
		{"another console user", `{"user":"bob","first_prompt":"2026-11-01T09:00:00Z","deferrals":3}`},
		{"not JSON", `2026-11-01T09:00:00Z alice`},
		{"first prompt in the future", `{"user":"alice","first_prompt":"2031-01-01T00:00:00Z","deferrals":0}`},
		{"negative count", `{"user":"alice","first_prompt":"2026-11-16T09:00:00Z","deferrals":-40}`},
		{"negative unanswered count", `{"user":"alice","first_prompt":"2026-11-16T09:00:00Z","deferrals":0,"unanswered":-9}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			win := &fakeWindow{events: []any{dialogEvent{kind: eventTimeout}}}
			m, _, requests := dialogManager(t, win, nil, "correct horse")
			m.now = func() time.Time { return promptDay }
			writeState(t, m, tc.state)

			ask(m, context.Background(), false)

			if got := (*requests)[0].DeferralsLeft; got != maxDeferrals {
				t.Errorf("window offered %d postponement(s), want a fresh budget of %d", got, maxDeferrals)
			}
			if st := readState(t, m); st.User != "alice" || !st.FirstPrompt.Equal(promptDay) || st.Deferrals != 0 {
				t.Errorf("state = %+v, want a fresh state for alice", st)
			}
		})
	}
}

func TestClearPromptStateRemovesTheBudget(t *testing.T) {
	m, _, _ := dialogManager(t, &fakeWindow{}, nil, "correct horse")
	writeState(t, m, `{"user":"alice","first_prompt":"2026-11-16T09:00:00Z","deferrals":3}`)

	m.clearPromptState()
	m.clearPromptState() // nothing to remove is not an error

	if _, err := os.Stat(m.promptStatePath); !os.IsNotExist(err) {
		t.Errorf("the state file is still there after the grant: %v", err)
	}
}

func TestManageSecureTokenClearsTheBudgetWhenTheTokenIsThere(t *testing.T) {
	osState := &fakeOS{exists: map[string]bool{"localadmin": true}, token: map[string]bool{"localadmin": true}}
	f := grantOS(t, osState)
	m := newTestManager(t, f)
	m.promptStatePath = filepath.Join(t.TempDir(), "token_prompt.json")
	writeState(t, m, `{"user":"alice","first_prompt":"2026-11-16T09:00:00Z","deferrals":3}`)

	status := m.ManageSecureToken(context.Background(), "localadmin", "new-pass", map[string]string{})

	if !strings.HasPrefix(status, "ENABLED") {
		t.Fatalf("status = %q, want ENABLED", status)
	}
	if _, err := os.Stat(m.promptStatePath); !os.IsNotExist(err) {
		t.Errorf("the state file survived a present token: %v", err)
	}
}

func TestEachPromptWithoutAPasswordIsCounted(t *testing.T) {
	wrong := make([]any, maxPasswordAttempts)
	for i := range wrong {
		wrong[i] = typed("wrong")
	}
	cases := []struct {
		name   string
		events []any
		want   int
	}{
		{"later", []any{dialogEvent{kind: eventLater}}, 3},
		{"timeout", []any{dialogEvent{kind: eventTimeout}}, 3},

		{"five wrong passwords", wrong, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, _, _ := dialogManager(t, &fakeWindow{events: tc.events}, nil, "correct horse")
			m.now = func() time.Time { return promptDay }
			writeState(t, m, `{"user":"alice","first_prompt":"2026-11-16T09:00:00Z","deferrals":0,"unanswered":2}`)

			ask(m, context.Background(), false)

			if got := readState(t, m).Unanswered; got != tc.want {
				t.Errorf("unanswered = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestScreenBlockStartsAfterSevenPromptsWithoutAPassword(t *testing.T) {
	cases := []struct {
		unanswered int
		want       bool
	}{
		{0, false},
		{blockScreenAfter - 1, false},
		{blockScreenAfter, true},
		{blockScreenAfter + 5, true},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%d unanswered", tc.unanswered), func(t *testing.T) {
			win := &fakeWindow{events: []any{dialogEvent{kind: eventTimeout}}}
			m, _, requests := dialogManager(t, win, nil, "correct horse")
			m.now = func() time.Time { return promptDay }
			writeState(t, m, fmt.Sprintf(`{"user":"alice","first_prompt":"2026-11-16T09:00:00Z","deferrals":0,"unanswered":%d}`, tc.unanswered))

			logged := captureLog(func() { ask(m, context.Background(), false) })

			if got := (*requests)[0].BlockScreen; got != tc.want {
				t.Errorf("blockScreen = %v, want %v", got, tc.want)
			}
			if has := strings.Contains(logged, "[SCREEN BLOCK] alice did not type the password in"); has != tc.want {
				t.Errorf("[SCREEN BLOCK] line present = %v, want %v: %s", has, tc.want, logged)
			}
		})
	}
}

func TestBlockScreenAfterIsSeven(t *testing.T) {
	if blockScreenAfter != 7 {
		t.Errorf("blockScreenAfter = %d. The README, the ticket and the user article say 7. Change them together.", blockScreenAfter)
	}
}

func TestBuildScriptShipsTheBackdropWhereTheWindowReadsIt(t *testing.T) {
	raw, err := os.ReadFile("../../scripts/build/build.sh")
	if err != nil {
		t.Fatalf("cannot read build.sh: %v", err)
	}
	build := string(raw)
	if !strings.Contains(build, `MAC_BACKDROP_PATH="`+backdropPath+`"`) {
		t.Errorf("build.sh does not install the backdrop at %s", backdropPath)
	}
	if !strings.Contains(build, `"$PAYLOAD_ROOT$MAC_BACKDROP_PATH"`) {
		t.Error("build.sh does not copy the backdrop into the package payload")
	}
}

func TestPipeWindowCloseIsBoundedWhenTheChildClosesItsOutput(t *testing.T) {
	win, err := startPipeWindow(exec.Command("/bin/sh", "-c", `read -r req; exec >&-; exec sleep 600`), dialogRequest{Attempt: 1, MaxAttempts: 5}, testSocket(t), os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := win.next(ctx); err == nil {
		t.Fatal("a window without an output delivered an event")
	}
	done := make(chan struct{})
	go func() { win.close(); close(done) }()
	select {
	case <-done:
	case <-time.After(windowCloseGrace + 10*time.Second):
		t.Fatal("close waits without a limit for a child that closed its output and kept running")
	}
}

func TestPipeWindowRefusesALineThatIsTooLong(t *testing.T) {
	win, err := startPipeWindow(exec.Command("/bin/sh", "-c", `read -r req; head -c 200000 /dev/zero | tr '\0' x; echo; printf '%s\n' '{"event":"later"}'; exec sleep 600`), dialogRequest{Attempt: 1, MaxAttempts: 5}, testSocket(t), os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ev, err := win.next(ctx)
	if err == nil {
		t.Fatalf("accepted %+v after a line that is too long", ev)
	}
	if strings.Contains(err.Error(), "xxxx") {
		t.Error("the error repeats the line")
	}
	done := make(chan struct{})
	go func() { win.close(); close(done) }()
	select {
	case <-done:
	case <-time.After(windowCloseGrace + 10*time.Second):
		t.Fatal("close did not return after a line that is too long")
	}
}

func TestAskPasswordGivesTheWindowOnlyTheTimeThatIsLeft(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	win := &fakeWindow{events: []any{dialogEvent{kind: eventTimeout}}}
	m, _, requests := dialogManager(t, win, nil, "correct horse")

	ask(m, ctx, false)

	if got := (*requests)[0].TimeoutSeconds; got > 120 || got < 90 {
		t.Errorf("timeoutSeconds = %d with two minutes of budget, want at most 120", got)
	}
}

func TestAskPasswordSkipsThePromptWhenTooLittleTimeIsLeft(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	win := &fakeWindow{events: []any{dialogEvent{kind: eventTimeout}}}
	m, _, requests := dialogManager(t, win, nil, "correct horse")

	var outcome passwordOutcome
	logged := captureLog(func() { _, outcome = ask(m, ctx, false) })

	if outcome != passwordTimeout || len(*requests) != 0 {
		t.Fatalf("outcome %v, windows %d: want a skipped prompt", outcome, len(*requests))
	}
	if !strings.Contains(logged, "[PROMPT SKIPPED: no-time]") {
		t.Errorf("log lacks the [PROMPT SKIPPED: no-time] line: %s", logged)
	}
	if _, err := os.Stat(m.promptStatePath); !os.IsNotExist(err) {
		t.Error("a skipped prompt wrote a deferral record")
	}
}

func TestBudgetThatEndsDuringThePromptIsNotCounted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	win := &fakeWindow{events: []any{func() (dialogEvent, error) { cancel(); return dialogEvent{}, context.Canceled }}}
	m, _, _ := dialogManager(t, win, nil, "correct horse")
	writeState(t, m, `{"user":"alice","first_prompt":"2026-11-16T09:00:00Z","deferrals":0,"unanswered":2}`)
	m.now = func() time.Time { return promptDay }

	_, outcome := ask(m, ctx, false)

	if outcome != passwordTimeout {
		t.Fatalf("outcome %v, want a timeout", outcome)
	}
	if got := readState(t, m).Unanswered; got != 2 {
		t.Errorf("unanswered = %d, want 2", got)
	}
}

func TestPromptIsSkippedWhileTheScreenIsLocked(t *testing.T) {
	win := &fakeWindow{events: []any{dialogEvent{kind: eventTimeout}}}
	m, f, requests := dialogManager(t, win, nil, "correct horse")
	inner := f.handle
	f.handle = func(c call) ([]byte, error) {
		if c.is("ioreg", "-n", "Root", "-d1", "-a") {
			return []byte(ioregLocked), nil
		}
		return inner(c)
	}

	var outcome passwordOutcome
	logged := captureLog(func() { _, outcome = ask(m, context.Background(), false) })

	if outcome != passwordTimeout || len(*requests) != 0 {
		t.Fatalf("outcome %v, windows %d: nobody can see a window under the lock screen", outcome, len(*requests))
	}
	if !strings.Contains(logged, "[PROMPT SKIPPED: screen-locked]") {
		t.Errorf("log lacks the [PROMPT SKIPPED: screen-locked] line: %s", logged)
	}
	if _, err := os.Stat(m.promptStatePath); !os.IsNotExist(err) {
		t.Error("a prompt under the lock screen started the deferral budget")
	}
}

func TestSessionLocked(t *testing.T) {
	cases := map[string]bool{
		ioregLocked:   true,
		ioregUnlocked: false,
		``:            false,
		`<key>CGSSessionScreenIsLocked</key><false/>`: false,
	}
	for out, want := range cases {
		if got := sessionLocked(out); got != want {
			t.Errorf("sessionLocked = %v, want %v for %q", got, want, out)
		}
	}
}

func TestSavePromptStateLeavesOneFile(t *testing.T) {
	m, _, _ := dialogManager(t, &fakeWindow{}, nil, "correct horse")
	m.savePromptState(promptState{User: "alice", FirstPrompt: promptDay, Deferrals: 1})
	m.savePromptState(promptState{User: "alice", FirstPrompt: promptDay, Deferrals: 2})

	entries, err := os.ReadDir(filepath.Dir(m.promptStatePath))
	if err != nil || len(entries) != 1 {
		t.Fatalf("directory holds %d entries (err %v), want only the record: a temporary file must not stay behind", len(entries), err)
	}
	if got := readState(t, m).Deferrals; got != 2 {
		t.Errorf("deferrals = %d, want 2", got)
	}
}

func TestReadPromptRecordsRefusesSymlink(t *testing.T) {
	m, _, _ := dialogManager(t, &fakeWindow{}, nil, "correct horse")
	dir := filepath.Dir(m.promptStatePath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte(`{"user":"alice","first_prompt":"2026-11-16T09:00:00Z","deferrals":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, m.promptStatePath); err != nil {
		t.Fatal(err)
	}
	if _, err := m.readPromptRecords(); err == nil {
		t.Fatal("readPromptRecords followed a symlink")
	}
}

func adminAfter(f *fakeRunner, from int) {
	inner := f.handle
	checks := 0
	f.handle = func(c call) ([]byte, error) {
		if c.is("dseditgroup", "-o", "checkmember", "-m", "alice", "admin") {
			checks++
			if checks >= from {
				return []byte("yes alice is a member of admin"), nil
			}
			return []byte("no alice is NOT a member of admin"), fakeExit{67}
		}
		return inner(c)
	}
}

func TestAdminStepWaitsForAdminByRequestThenAsksForThePassword(t *testing.T) {
	tick := context.DeadlineExceeded
	win := &fakeWindow{events: []any{dialogEvent{kind: eventAdminRequested}, tick, tick, typed("correct horse")}}
	m, f, requests := dialogManager(t, win, nil, "correct horse")
	adminAfter(f, 2)
	var opened []string
	m.openApp = func(_ context.Context, uid, user, app string) error {
		opened = append(opened, uid+"/"+user+"/"+app)
		return nil
	}

	var pass string
	var outcome passwordOutcome
	logged := captureLog(func() { pass, outcome = ask(m, context.Background(), true) })

	if outcome != passwordOK || pass != "correct horse" {
		t.Fatalf("got (%q, %v), want the verified password", pass, outcome)
	}
	if !(*requests)[0].NeedAdmin {
		t.Error("the window was not told to start with the admin step")
	}
	if !reflect.DeepEqual(opened, []string{"501/alice/" + abrAppName}) {
		t.Errorf("opened apps = %v, want Admin By Request one time, in the session of alice", opened)
	}
	if !reflect.DeepEqual(win.views, []string{viewPassword, viewWorking, viewDone}) {
		t.Errorf("views = %v, want the password step, the progress view and the success view", win.views)
	}
	for _, line := range []string{"[WAIT] alice asked for an Admin By Request session", "[SUCCESS] alice obtained admin rights via Admin By Request. Continuing."} {
		if !strings.Contains(logged, line) {
			t.Errorf("log lacks %q: %s", line, logged)
		}
	}
}

func TestAdminStepIsSkippedForAnAdmin(t *testing.T) {
	win := &fakeWindow{events: []any{typed("correct horse")}}
	m, f, requests := dialogManager(t, win, nil, "correct horse")

	_, outcome := ask(m, context.Background(), false)

	if outcome != passwordOK {
		t.Fatalf("got %v, want passwordOK", outcome)
	}
	if (*requests)[0].NeedAdmin || f.count("dseditgroup") != 1 || len(win.views) == 0 || win.views[0] != viewWorking {
		t.Errorf("needAdmin=%v, group checks=%d, views=%v: an admin must go from the password to the grant at once", (*requests)[0].NeedAdmin, f.count("dseditgroup"), win.views)
	}
}

func TestLaterAndTimeoutWorkInTheAdminStep(t *testing.T) {
	cases := []struct {
		name          string
		event         dialogEvent
		want          passwordOutcome
		wantDeferrals int
	}{
		{"later", dialogEvent{kind: eventLater}, passwordLater, 1},
		{"timeout", dialogEvent{kind: eventTimeout}, passwordTimeout, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			win := &fakeWindow{events: []any{tc.event}}
			m, _, _ := dialogManager(t, win, nil, "correct horse")
			m.now = func() time.Time { return promptDay }

			_, outcome := ask(m, context.Background(), true)

			if outcome != tc.want {
				t.Fatalf("got %v, want %v", outcome, tc.want)
			}
			if st := readState(t, m); st.Deferrals != tc.wantDeferrals || st.Unanswered != 1 {
				t.Errorf("state = %+v, want %d deferral(s) and 1 unanswered prompt", st, tc.wantDeferrals)
			}
			if len(win.views) != 0 {
				t.Errorf("views = %v: the window went on without admin rights", win.views)
			}
		})
	}
}

func TestPromptFailsWithoutAWindow(t *testing.T) {
	m, f, _ := dialogManager(t, nil, errors.New("golaps_auth is not installed"), "correct horse")

	var pass string
	var outcome passwordOutcome
	logged := captureLog(func() { pass, outcome = ask(m, context.Background(), false) })

	if outcome != passwordUnavailable || pass != "" {
		t.Fatalf("got (%q, %v), want passwordUnavailable", pass, outcome)
	}
	if !strings.Contains(logged, "[PROMPT FAILED: window]") {
		t.Errorf("log lacks the [PROMPT FAILED: window] line for the fleet report: %s", logged)
	}
	if f.count("osascript") != 0 {
		t.Error("an osascript dialog ran")
	}
	if _, err := os.Stat(m.promptStatePath); !os.IsNotExist(err) {
		t.Error("a prompt that never opened wrote a deferral record")
	}
}

func TestWindowThatNeverAppearsStartsNothing(t *testing.T) {
	win := &fakeWindow{neverShown: true, events: []any{io.EOF}}
	m, _, _ := dialogManager(t, win, nil, "correct horse")
	m.now = func() time.Time { return promptDay }
	writeState(t, m, `{"user":"alice","first_prompt":"2026-11-16T09:00:00Z","deferrals":3,"unanswered":20}`)

	var outcome passwordOutcome
	logged := captureLog(func() { _, outcome = ask(m, context.Background(), false) })

	if outcome != passwordUnavailable {
		t.Errorf("outcome = %v, want passwordUnavailable", outcome)
	}
	if strings.Contains(logged, "[SCREEN BLOCK]") || strings.Contains(logged, "[DEFERRAL LIMIT]") || !strings.Contains(logged, "[PROMPT FAILED: window]") {
		t.Errorf("the log must report a failed window, and no limit or block for a window that nobody saw: %s", logged)
	}
	if st := readState(t, m); st.Unanswered != 20 || st.Deferrals != 3 {
		t.Errorf("state = %+v, want it unchanged", st)
	}
	if win.closed == 0 {
		t.Error("the window process was not closed")
	}
}

func TestWindowThatEndsBeforeItAppearsCountsTowardTheStreak(t *testing.T) {
	cases := []struct {
		name  string
		first any
	}{
		{"the process ended", io.EOF},
		{"the process stayed silent", context.DeadlineExceeded},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			win := &fakeWindow{neverShown: true, events: []any{tc.first}}
			m, _, _ := dialogManager(t, win, nil, "correct horse")
			m.now = func() time.Time { return promptDay }
			writeState(t, m, `{"user":"alice","first_prompt":"2026-11-16T09:00:00Z","deferrals":1,"unanswered":4,"window_failed_runs":1}`)

			outcome, tally := m.askPassword(context.Background(), "501", "alice", false, nil)

			if outcome != passwordUnavailable || !tally.windowFailed || tally.windowFailedRuns != 2 {
				t.Fatalf("got (%v, %+v), want (passwordUnavailable, windowFailed with a streak of 2)", outcome, tally)
			}
			if st := readState(t, m); st.WindowFailedRuns != 2 || st.Unanswered != 4 || st.Deferrals != 1 {
				t.Errorf("state = %+v, want window_failed_runs 2 and the budget unchanged", st)
			}
		})
	}
}

func TestWindowThatEndsBeforeItAppearsLeavesARecord(t *testing.T) {
	m, _, _ := dialogManager(t, &fakeWindow{neverShown: true, events: []any{io.EOF}}, nil, "correct horse")
	m.now = func() time.Time { return promptDay }

	m.askPassword(context.Background(), "501", "alice", false, nil)

	if st := readState(t, m); st.User != "alice" || st.WindowFailedRuns != 1 {
		t.Errorf("state = %+v, want a record of alice with window_failed_runs 1", st)
	}
}

func TestWindowThatDiesAfterItAppearedIsCounted(t *testing.T) {
	cases := []struct {
		name      string
		win       *fakeWindow
		needAdmin bool
	}{
		{"in the password step", &fakeWindow{events: []any{io.EOF}}, false},
		{"after a wrong password", &fakeWindow{events: []any{typed("typo"), io.EOF}}, false},
		{"when the wrong-password notice cannot be sent", &fakeWindow{events: []any{typed("typo")}, wrongErr: errors.New("broken pipe")}, false},
		{"in the admin step", &fakeWindow{events: []any{dialogEvent{kind: eventAdminRequested}, io.EOF}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, f, _ := dialogManager(t, tc.win, nil, "correct horse")
			m.now = func() time.Time { return promptDay }
			writeState(t, m, `{"user":"alice","first_prompt":"2026-11-16T09:00:00Z","deferrals":0,"unanswered":2}`)

			var outcome passwordOutcome
			logged := captureLog(func() { _, outcome = ask(m, context.Background(), tc.needAdmin) })

			if outcome != passwordUnavailable {
				t.Errorf("outcome = %v, want passwordUnavailable", outcome)
			}
			if got := readState(t, m).Unanswered; got != 3 {
				t.Errorf("unanswered = %d, want 3", got)
			}
			if !strings.Contains(logged, "[PROMPT FAILED: window]") || f.count("osascript") != 0 {
				t.Errorf("want the [PROMPT FAILED: window] line and no osascript dialog: %s", logged)
			}
		})
	}
}

func TestPasswordInTheAdminStepIsNotUsed(t *testing.T) {
	win := &fakeWindow{events: []any{typed("correct horse")}}
	m, f, _ := dialogManager(t, win, nil, "correct horse")

	pass, outcome := ask(m, context.Background(), true)

	if outcome == passwordOK || pass != "" || f.count("mac_helper") != 0 {
		t.Errorf("got (%q, %v) with %d verification(s): a password from the admin step must not be used", pass, outcome, f.count("mac_helper"))
	}
}

func TestGrantRunsInsideTheWindowAndTheResultIsShown(t *testing.T) {
	cases := []struct {
		name      string
		grantErr  error
		want      passwordOutcome
		wantViews []string
		wantLog   string
	}{
		{"the grant works", nil, passwordOK, []string{viewWorking, viewDone}, "[SUCCESS] GUI Token Grant Successful!"},
		{"the grant fails", errors.New("token is still DISABLED"), passwordGrantFailed, []string{viewWorking, viewError}, "[ERROR] Swift token grant failed: token is still DISABLED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			win := &fakeWindow{events: []any{typed("correct horse")}}
			m, f, _ := dialogManager(t, win, nil, "correct horse")
			adminAfter(f, 1) // the user is an admin, so a failed grant is not a lost admin session
			writeState(t, m, `{"user":"alice","first_prompt":"2026-11-16T09:00:00Z","deferrals":1,"unanswered":1}`)
			m.now = func() time.Time { return promptDay }
			var grants []string

			var outcome passwordOutcome
			logged := captureLog(func() {
				outcome, _ = m.askPassword(context.Background(), "501", "alice", false, func(_ context.Context, password string) error {
					grants = append(grants, password)
					return tc.grantErr
				})
			})

			if outcome != tc.want {
				t.Fatalf("outcome = %v, want %v", outcome, tc.want)
			}
			if !reflect.DeepEqual(grants, []string{"correct horse"}) {
				t.Errorf("grant calls = %v, want one call with the verified password", grants)
			}
			if !reflect.DeepEqual(win.views, tc.wantViews) {
				t.Errorf("views = %v, want %v", win.views, tc.wantViews)
			}
			if !strings.Contains(logged, tc.wantLog) || !strings.Contains(logged, "[INFO] Valid GUI password received. Delegating grant to Swift Helper...") {
				t.Errorf("log lacks the grant lines: %s", logged)
			}
			_, statErr := os.Stat(m.promptStatePath)
			if gone := os.IsNotExist(statErr); gone != (tc.want == passwordOK) {
				t.Errorf("deferral record removed = %v; it must go only after a grant that worked", gone)
			}
		})
	}
}

func TestGrantIsRepeatedAfterALostAdminSession(t *testing.T) {
	tick := context.DeadlineExceeded
	win := &fakeWindow{events: []any{typed("correct horse"), dialogEvent{kind: eventAdminRequested}, tick}}
	m, f, _ := dialogManager(t, win, nil, "correct horse")
	adminSequence(f, true, false, true) // an admin at the typed password, not an admin at the check after the failed grant, an admin at the next poll
	grants := 0

	outcome, _ := m.askPassword(context.Background(), "501", "alice", false, func(context.Context, string) error {
		grants++
		if grants == 1 {
			return errors.New("5101 Credential is not an admin")
		}
		return nil
	})

	if outcome != passwordOK || grants != 2 {
		t.Fatalf("outcome %v after %d grant call(s), want passwordOK after 2", outcome, grants)
	}
	if !reflect.DeepEqual(win.views, []string{viewWorking, viewAdmin, viewWorking, viewDone}) {
		t.Errorf("views = %v, want progress, admin step, progress, success", win.views)
	}
	if f.count("mac_helper") != 1 {
		t.Errorf("the password was checked %d time(s); the user must not type it again", f.count("mac_helper"))
	}
}

func TestGrantRunsAlsoWhenTheWindowCannotShowTheProgress(t *testing.T) {
	win := &fakeWindow{events: []any{typed("correct horse")}, showErr: errors.New("broken pipe")}
	m, _, _ := dialogManager(t, win, nil, "correct horse")

	pass, outcome := ask(m, context.Background(), false)

	if outcome != passwordOK || pass != "correct horse" {
		t.Errorf("got (%q, %v), want the grant with the verified password", pass, outcome)
	}
}

func TestEachPromptEndsWithOneReportLine(t *testing.T) {
	wrong := make([]any, maxPasswordAttempts)
	for i := range wrong {
		wrong[i] = typed("wrong")
	}
	grantFails := func(context.Context, string) error { return errors.New("token is still DISABLED") }
	grantWorks := func(context.Context, string) error { return nil }
	shortBudget := func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(context.Background(), 5*time.Second)
	}
	endedBudget := func() (context.Context, context.CancelFunc) {
		return context.WithCancel(context.Background())
	}
	cases := []struct {
		name    string
		win     *fakeWindow
		openErr error
		locked  bool
		ctx     func() (context.Context, context.CancelFunc)
		ends    bool // the budget ends while the window is open
		grant   func(context.Context, string) error
		want    string
	}{
		{name: "the grant worked", win: &fakeWindow{events: []any{typed("correct horse")}}, grant: grantWorks, want: "PROMPT: ok"},
		{name: "the user clicked Later", win: &fakeWindow{events: []any{dialogEvent{kind: eventLater}}}, grant: grantWorks, want: "PROMPT: later"},
		{name: "nobody answered", win: &fakeWindow{events: []any{dialogEvent{kind: eventTimeout}}}, grant: grantWorks, want: "PROMPT: timeout"},
		{name: "five wrong passwords", win: &fakeWindow{events: wrong}, grant: grantWorks, want: "PROMPT: wrong-password"},
		{name: "the grant failed", win: &fakeWindow{events: []any{typed("correct horse")}}, grant: grantFails, want: "PROMPT: grant-failed"},
		{name: "the window could not start", openErr: errors.New("golaps_auth is not installed"), grant: grantWorks, want: "PROMPT: window-failed"},
		{name: "the window ended early", win: &fakeWindow{events: []any{io.EOF}}, grant: grantWorks, want: "PROMPT: window-failed"},
		{name: "the screen was locked", win: &fakeWindow{}, locked: true, grant: grantWorks, want: "PROMPT: skipped-screen-locked"},
		{name: "no run budget was left", win: &fakeWindow{}, ctx: shortBudget, grant: grantWorks, want: "PROMPT: skipped-no-time"},
		{name: "the run budget ended in the prompt", win: &fakeWindow{}, ctx: endedBudget, ends: true, grant: grantWorks, want: "PROMPT: budget-ended"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.Background(), context.CancelFunc(func() {})
			if tc.ctx != nil {
				ctx, cancel = tc.ctx()
			}
			defer cancel()
			if tc.ends {
				tc.win.events = []any{func() (dialogEvent, error) { cancel(); return dialogEvent{}, context.Canceled }}
			}
			m, f, _ := dialogManager(t, tc.win, tc.openErr, "correct horse")
			adminAfter(f, 1) // the user is an admin, so a failed grant is not a lost admin session
			if tc.locked {
				inner := f.handle
				f.handle = func(c call) ([]byte, error) {
					if c.name == "ioreg" {
						return []byte(ioregLocked), nil
					}
					return inner(c)
				}
			}

			logged := captureLog(func() { m.askPassword(ctx, "501", "alice", false, tc.grant) })

			var lines []string
			for _, line := range strings.Split(logged, "\n") {
				if i := strings.Index(line, "PROMPT: "); i >= 0 {
					lines = append(lines, line[i:])
				}
			}
			if !reflect.DeepEqual(lines, []string{tc.want}) {
				t.Errorf("report lines = %q, want exactly %q", lines, tc.want)
			}
		})
	}
}

func TestDialogRequestCarriesNoText(t *testing.T) {
	typ := reflect.TypeOf(dialogRequest{})
	for i := 0; i < typ.NumField(); i++ {
		switch typ.Field(i).Type.Kind() {
		case reflect.Int, reflect.Bool:
		default:
			t.Errorf("dialogRequest.%s is a %s; only int and bool fields are allowed", typ.Field(i).Name, typ.Field(i).Type.Kind())
		}
	}
}

func TestParseDialogEvent(t *testing.T) {
	cases := []struct {
		name    string
		line    string
		want    dialogEvent
		wantErr bool
	}{
		{"password is not an output line", `{"event":"password","password":"p@ss word"}`, dialogEvent{}, true},
		{"later", `{"event":"later"}`, dialogEvent{kind: eventLater}, false},
		{"timeout", `{"event":"timeout"}`, dialogEvent{kind: eventTimeout}, false},
		{"shown", `{"event":"shown"}`, dialogEvent{kind: eventShown}, false},
		{"password on shown", `{"event":"shown","password":"x"}`, dialogEvent{}, true},
		{"granted is not a window event", `{"event":"granted"}`, dialogEvent{}, true},
		{"password on another event", `{"event":"later","password":"x"}`, dialogEvent{}, true},
		{"unknown field", `{"event":"later","admin":true}`, dialogEvent{}, true},
		{"osascript protocol", `UPDATE::secret`, dialogEvent{}, true},
		{"empty line", ``, dialogEvent{}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseDialogEvent(tc.line)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("event = %+v, want %+v", got, tc.want)
			}
			if err != nil && strings.Contains(err.Error(), "secret") {
				t.Errorf("the parse error repeats the input: %v", err)
			}
		})
	}
}

func testSocket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "laps")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "auth.sock")
}

func startScript(t *testing.T, script string, req dialogRequest) *pipeWindow {
	t.Helper()
	win, err := startPipeWindow(exec.Command("/bin/sh", "-c", script), req, testSocket(t), os.Getuid())
	if err != nil {
		t.Fatalf("could not start the script: %v", err)
	}
	t.Cleanup(win.close)
	return win
}

func TestPipeWindowSendsRequestAndRelaysAnswers(t *testing.T) {
	dir := t.TempDir()
	sock := testSocket(t)
	script := `read -r req; printf '%s' "$req" > "$0/request"; printf '%s\n' 'it'"'"'s "me"' | nc -U "$1"; read -r cmd; printf '%s' "$cmd" > "$0/command"; printf '%s\n' '{"event":"later"}'; read -r rest`
	win, err := startPipeWindow(exec.Command("/bin/sh", "-c", script, dir, sock), dialogRequest{Attempt: 1, MaxAttempts: 5, DeferralsLeft: 3, TimeoutSeconds: 300}, sock, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	defer win.close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ev, err := win.next(ctx)
	if err != nil || ev != typed(`it's "me"`) {
		t.Fatalf("first event = (%+v, %v), want the typed password", ev, err)
	}
	if err := win.wrong(2); err != nil {
		t.Fatalf("wrong(2) failed: %v", err)
	}
	ev, err = win.next(ctx)
	if err != nil || ev.kind != eventLater {
		t.Fatalf("second event = (%+v, %v), want later", ev, err)
	}

	req, _ := os.ReadFile(filepath.Join(dir, "request"))
	if string(req) != `{"attempt":1,"maxAttempts":5,"deferralsLeft":3,"blockScreen":false,"needAdmin":false,"timeoutSeconds":300}` {
		t.Errorf("request line = %s", req)
	}
	cmd, _ := os.ReadFile(filepath.Join(dir, "command"))
	if string(cmd) != `{"cmd":"wrong","attempt":2}` {
		t.Errorf("command line = %s", cmd)
	}
}

func TestReadPasswordLogsADroppedConnection(t *testing.T) {
	sock := testSocket(t)
	script := `read -r req; printf '{"event":"shown"}\n'; : | nc -U "$1"; printf 'abc' | nc -U "$1"; printf '\n' | nc -U "$1"; sleep 0.3; printf '{"event":"later"}\n'; read -r rest`
	win, err := startPipeWindow(exec.Command("/bin/sh", "-c", script, "sh", sock), dialogRequest{Attempt: 1, MaxAttempts: 5}, sock, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	defer win.close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var events []dialogEvent
	logged := captureLog(func() {
		for len(events) < 2 {
			ev, err := win.next(ctx)
			if err != nil {
				t.Fatalf("next failed: %v", err)
			}
			events = append(events, ev)
		}
		// Read the log buffer only after close, because the socket goroutine writes to it until then.
		win.close()
	})
	if events[0].kind != eventShown || events[1].kind != eventLater {
		t.Fatalf("events = %+v, want shown then later: the two bad connections must not become events", events)
	}
	if !strings.Contains(logged, "checked that the password socket is reachable") || strings.Count(logged, "ended before a full line arrived") != 1 {
		t.Fatalf("the empty probe connection must log INFO and only the truncated line must log the WARNING: %s", logged)
	}
	if !strings.Contains(logged, "ended before a full line arrived") || !strings.Contains(logged, "received an empty line") {
		t.Errorf("the dropped connections left no warning: %s", logged)
	}
}

func TestDroppedConnectionsHaveALogLimit(t *testing.T) {
	sock := testSocket(t)
	script := `read -r req; printf '{"event":"shown"}\n'; i=0; while [ $i -lt 12 ]; do : | nc -U "$1"; i=$((i+1)); done; printf '{"event":"later"}\n'; read -r rest`
	win, err := startPipeWindow(exec.Command("/bin/sh", "-c", script, "sh", sock), dialogRequest{Attempt: 1, MaxAttempts: 5}, sock, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	logged := captureLog(func() {
		defer win.close()
		for _, want := range []dialogEventKind{eventShown, eventLater} {
			if ev, err := win.next(ctx); err != nil || ev.kind != want {
				t.Fatalf("event = (%+v, %v), want kind %v", ev, err, want)
			}
		}
	})
	if n := strings.Count(logged, "checked that the password socket is reachable"); n != socketLogLimit {
		t.Errorf("%d lines for 12 empty connections, want %d: %s", n, socketLogLimit, logged)
	}
	if !strings.Contains(logged, `12 connections of the kind "probe"`) {
		t.Errorf("the close of the socket must report the total of 12: %s", logged)
	}
}

func TestPasswordLineWithoutAnEndIsReportedAsTooLong(t *testing.T) {
	sock := testSocket(t)
	script := `read -r req; printf '{"event":"shown"}\n'; head -c 70000 /dev/zero | tr '\0' a | nc -U "$1"; printf '{"event":"later"}\n'; read -r rest`
	win, err := startPipeWindow(exec.Command("/bin/sh", "-c", script, "sh", sock), dialogRequest{Attempt: 1, MaxAttempts: 5}, sock, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	logged := captureLog(func() {
		defer win.close()
		for _, want := range []dialogEventKind{eventShown, eventLater} {
			if ev, err := win.next(ctx); err != nil || ev.kind != want {
				t.Fatalf("event = (%+v, %v), want kind %v", ev, err, want)
			}
		}
	})
	if !strings.Contains(logged, "is longer than") || strings.Contains(logged, "ended before a full line arrived") {
		t.Errorf("want the too-long line and no early-end line: %s", logged)
	}
}

func TestPasswordOnTheOutputOfTheWindowIsRefused(t *testing.T) {
	win := startScript(t, `read -r req; printf '%s\n' '{"event":"password","password":"stolen"}'; read -r rest`, dialogRequest{Attempt: 1, MaxAttempts: 5})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ev, err := win.next(ctx)
	if err == nil {
		t.Fatalf("accepted %+v from the output of the window", ev)
	}
	if strings.Contains(err.Error(), "stolen") {
		t.Error("the error repeats the password")
	}
}

func TestPasswordSocketBelongsToTheWindowSession(t *testing.T) {
	sock := testSocket(t)
	if err := os.WriteFile(sock, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	win, err := startPipeWindow(exec.Command("/bin/sh", "-c", `read -r req; read -r rest`), dialogRequest{Attempt: 1, MaxAttempts: 5}, sock, os.Getuid())
	if err != nil {
		t.Fatalf("a stale file at the socket path stopped the window: %v", err)
	}
	info, err := os.Stat(sock)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("no socket at %s while the window is open (err %v)", sock, err)
	}
	win.close()
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Errorf("the socket is still there after close: %v", err)
	}
}

func TestPasswordSocketGetsItsModeAtTheBind(t *testing.T) {
	old := unix.Umask(0o077)
	t.Cleanup(func() { unix.Umask(old) })

	sock := testSocket(t)
	win, err := startPipeWindow(exec.Command("/bin/sh", "-c", `read -r req; read -r rest`), dialogRequest{Attempt: 1, MaxAttempts: 5}, sock, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	defer win.close()

	info, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o666 {
		t.Errorf("socket mode = %o, want 666: the window of the console user must be able to connect", got)
	}
	if now := unix.Umask(0o077); now != 0o077 {
		t.Errorf("umask after the start = %o, want the umask of the run back (077)", now)
	}

	raw, err := os.ReadFile("macos_dialog.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "os.Chmod(") {
		t.Error("macos_dialog.go changes a mode by path; set the mode of the socket at the bind")
	}
}

func TestPasswordSocketIgnoresAnEmptyConnectionAndAnotherUser(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	t.Run("an empty connection and an empty line are not a password", func(t *testing.T) {
		sock := testSocket(t)
		win, err := startPipeWindow(exec.Command("/bin/sh", "-c", `read -r req; nc -U "$0" </dev/null; printf '\n' | nc -U "$0"; printf '%s\n' 'real' | nc -U "$0"; read -r rest`, sock), dialogRequest{Attempt: 1, MaxAttempts: 5}, sock, os.Getuid())
		if err != nil {
			t.Fatal(err)
		}
		defer win.close()
		if ev, err := win.next(ctx); err != nil || ev != typed("real") {
			t.Fatalf("event = (%+v, %v), want the password of the second connection", ev, err)
		}
	})

	t.Run("a connection of another user is dropped", func(t *testing.T) {
		sock := testSocket(t)
		win, err := startPipeWindow(exec.Command("/bin/sh", "-c", `read -r req; printf '%s\n' 'foreign' | nc -U "$0"; printf '%s\n' '{"event":"later"}'; read -r rest`, sock), dialogRequest{Attempt: 1, MaxAttempts: 5}, sock, os.Getuid()+1)
		if err != nil {
			t.Fatal(err)
		}
		defer win.close()
		if ev, err := win.next(ctx); err != nil || ev.kind != eventLater {
			t.Fatalf("event = (%+v, %v), want later: the password of another user must be dropped", ev, err)
		}
	})
}

func TestPipeWindowCloseEndsTheWindowThroughEndOfInput(t *testing.T) {
	dir := t.TempDir()
	win, err := startPipeWindow(exec.Command("/bin/sh", "-c", `read -r req; read -r nothing; printf done > "$0/ended"`, dir), dialogRequest{Attempt: 1, MaxAttempts: 5}, testSocket(t), os.Getuid())
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	win.close()

	if _, err := os.Stat(filepath.Join(dir, "ended")); err != nil {
		t.Errorf("the script did not end through end-of-input: %v", err)
	}
	if took := time.Since(start); took >= windowCloseGrace {
		t.Errorf("close took %s; it waited for the kill instead of the end of input", took)
	}
	win.close() // a second close must be harmless
}

func TestPipeWindowKillsAWindowThatIgnoresEndOfInput(t *testing.T) {
	win, err := startPipeWindow(exec.Command("/bin/sh", "-c", `exec sleep 600`), dialogRequest{Attempt: 1, MaxAttempts: 5}, testSocket(t), os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { win.close(); close(done) }()
	select {
	case <-done:
	case <-time.After(windowCloseGrace + 10*time.Second):
		t.Fatal("close did not return for a window that ignores the end of input")
	}
}

func TestPipeWindowRejectsUnknownEvent(t *testing.T) {
	win := startScript(t, `read -r req; printf '%s\n' '{"event":"granted"}'; read -r rest`, dialogRequest{Attempt: 1, MaxAttempts: 5})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if ev, err := win.next(ctx); err == nil {
		t.Fatalf("accepted %+v from the window; only password, later and timeout are answers", ev)
	}
}

func TestPipeWindowReportsAWindowThatDied(t *testing.T) {
	win := startScript(t, `read -r req; exit 0`, dialogRequest{Attempt: 1, MaxAttempts: 5})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := win.next(ctx); !errors.Is(err, io.EOF) {
		t.Fatalf("error = %v, want io.EOF: a window that ends without an answer is a transport error", err)
	}
	if _, err := win.next(ctx); err == nil {
		t.Fatal("a dead window delivered a second event")
	}
}

func TestPipeWindowNextHonoursTheDeadline(t *testing.T) {
	win := startScript(t, `read -r req; read -r rest`, dialogRequest{Attempt: 1, MaxAttempts: 5})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := win.next(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want the deadline of the caller", err)
	}
}

func TestAuthWindowSourceKeepsTheContract(t *testing.T) {
	raw, err := os.ReadFile("auth_window.swift")
	if err != nil {
		t.Fatalf("cannot read the window source: %v", err)
	}
	var code []string
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "//") {
			code = append(code, line)
		}
	}
	src := strings.Join(code, "\n")

	for _, required := range []string{helpArticleURL, teamITChannelURL, backdropPath, authSocketPath, "signal(SIGPIPE, SIG_IGN)", "SO_NOSIGPIPE", "Waiting for the next attempt", "pauseEnding", "Your administrator access ended", "adminLost", `"later"`, `"timeout"`, `"shown"`, `"abr"`, `"wrong"`, `"show"`, `"` + viewAdmin + `"`, `"` + viewPassword + `"`, `"` + viewWorking + `"`, `"` + viewDone + `"`, `"` + viewError + `"`, `"` + viewFailed + `"`, `"` + viewPaused + `"`, "deferralsLeft", "blockScreen", "maxAttempts", "timeoutSeconds", "seconds", "didWakeNotification"} {
		if !strings.Contains(src, required) {
			t.Errorf("auth_window.swift does not contain %s", required)
		}
	}
	for _, forbidden := range []string{"CommandLine.arguments", "ProcessInfo.processInfo.arguments", "import OpenDirectory", "verifyPassword", ".terminate(", `"granted"`, `"event": "password"`} {
		if strings.Contains(src, forbidden) {
			t.Errorf("auth_window.swift contains %s", forbidden)
		}
	}
}

func TestWindowRequestFieldsMatchTheSwiftStruct(t *testing.T) {
	raw, err := os.ReadFile("auth_window.swift")
	if err != nil {
		t.Fatalf("cannot read the window source: %v", err)
	}
	block := regexp.MustCompile(`(?s)struct WindowRequest: Decodable \{(.*?)\n\}`).FindStringSubmatch(string(raw))
	if block == nil {
		t.Fatal("auth_window.swift has no struct WindowRequest")
	}
	swift := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^\s*let (\w+):`).FindAllStringSubmatch(block[1], -1) {
		swift[m[1]] = true
	}
	typ := reflect.TypeOf(dialogRequest{})
	for i := 0; i < typ.NumField(); i++ {
		key := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
		if !swift[key] {
			t.Errorf("Go sends %q, but the Swift struct WindowRequest has no such field", key)
		}
		delete(swift, key)
	}
	for key := range swift {
		t.Errorf("the Swift struct WindowRequest expects %q, but Go does not send it", key)
	}
}

func TestAuthWindowTestHooksStayInTheTestBuild(t *testing.T) {
	raw, err := os.ReadFile("auth_window.swift")
	if err != nil {
		t.Fatalf("cannot read the window source: %v", err)
	}
	release := regexp.MustCompile(`(?s)#if LAPS_TEST.*?#else`).ReplaceAllString(string(raw), "")
	if strings.Contains(release, "LAPS_TEST") || strings.Contains(release, "getenv") {
		t.Error("auth_window.swift reads the environment or names the test build outside the #if LAPS_TEST block")
	}
	if !strings.Contains(release, `static let ownerUID: uid_t = 0`) {
		t.Error("the release build does not require root at the other end of the password socket")
	}
	build, err := os.ReadFile("../../scripts/build/build.sh")
	if err != nil {
		t.Fatalf("cannot read build.sh: %v", err)
	}
	if strings.Contains(string(build), "LAPS_TEST") {
		t.Error("build.sh turns on the test build of the window")
	}
}

func TestBuildScriptShipsTheAuthWindow(t *testing.T) {
	raw, err := os.ReadFile("../../scripts/build/build.sh")
	if err != nil {
		t.Fatalf("cannot read build.sh: %v", err)
	}
	build := string(raw)
	if !strings.Contains(build, `MAC_AUTH_WINDOW_PATH="`+authWindowPath+`"`) {
		t.Errorf("build.sh does not install the window at %s, the path that Go starts", authWindowPath)
	}
	if !strings.Contains(build, `swiftc internal/osmgmt/auth_window.swift`) || !strings.Contains(build, `-o "$PAYLOAD_ROOT$MAC_AUTH_WINDOW_PATH"`) {
		t.Error("build.sh does not compile auth_window.swift into the package payload")
	}
}

func TestRealAuthWindow(t *testing.T) {
	bin := os.Getenv("LAPS_AUTH_WINDOW_BIN")
	if bin == "" {
		t.Skip("set LAPS_AUTH_WINDOW_BIN to an auth_window.swift that was compiled with -D LAPS_TEST to run this test")
	}
	realWindow := func(sock string) *exec.Cmd {
		cmd := exec.Command(bin)
		cmd.Env = append(os.Environ(), "LAPS_TEST_AUTH_SOCKET="+sock)
		return cmd
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("announces its own timeout", func(t *testing.T) {
		sock := testSocket(t)
		win, err := startPipeWindow(realWindow(sock), dialogRequest{Attempt: 1, MaxAttempts: 5, DeferralsLeft: 2, TimeoutSeconds: 2}, sock, os.Getuid())
		if err != nil {
			t.Fatal(err)
		}
		defer win.close()
		if ev, err := win.next(ctx); err != nil || ev.kind != eventShown {
			t.Fatalf("first event = (%+v, %v), want shown", ev, err)
		}
		ev, err := win.next(ctx)
		if err != nil || ev.kind != eventTimeout {
			t.Fatalf("event = (%+v, %v), want timeout", ev, err)
		}
	})

	t.Run("closes on end of input without an answer", func(t *testing.T) {
		sock := testSocket(t)
		win, err := startPipeWindow(realWindow(sock), dialogRequest{Attempt: 2, MaxAttempts: 5, TimeoutSeconds: 60}, sock, os.Getuid())
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(1500 * time.Millisecond)
		if err := win.wrong(3); err != nil {
			t.Fatalf("wrong(3) failed: %v", err)
		}
		time.Sleep(500 * time.Millisecond)
		start := time.Now()
		win.close()
		if took := time.Since(start); took >= windowCloseGrace {
			t.Errorf("close took %s; the window ignored the end of input", took)
		}
		if _, err := win.next(ctx); !errors.Is(err, io.EOF) {
			t.Errorf("after close: %v, want io.EOF and no invented answer", err)
		}
	})

	t.Run("does not open without the password socket", func(t *testing.T) {
		cmd := realWindow(filepath.Join(t.TempDir(), "absent.sock"))
		cmd.Stdin = strings.NewReader(`{"attempt":1,"maxAttempts":5,"deferralsLeft":2,"timeoutSeconds":5}` + "\n")
		out, err := cmd.Output()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 3 || len(out) != 0 {
			t.Errorf("got err=%v out=%q, want exit status 3 and no output", err, out)
		}
	})

	t.Run("goes from the admin step to the password step", func(t *testing.T) {
		sock := testSocket(t)
		win, err := startPipeWindow(realWindow(sock), dialogRequest{Attempt: 1, MaxAttempts: 5, DeferralsLeft: 2, NeedAdmin: true, TimeoutSeconds: 3}, sock, os.Getuid())
		if err != nil {
			t.Fatal(err)
		}
		defer win.close()
		if ev, err := win.next(ctx); err != nil || ev.kind != eventShown {
			t.Fatalf("first event = (%+v, %v), want shown", ev, err)
		}
		time.Sleep(time.Second)
		if err := win.show(viewPassword); err != nil {
			t.Fatalf("show(password) failed: %v", err)
		}
		start := time.Now()
		ev, err := win.next(ctx)
		if err != nil || ev.kind != eventTimeout {
			t.Fatalf("event = (%+v, %v), want timeout", ev, err)
		}
		if waited := time.Since(start); waited < 2500*time.Millisecond {
			t.Errorf("the timeout came %s after the step change; the change did not start the limit again", waited)
		}
	})

	t.Run("shows the progress and closes itself after the result", func(t *testing.T) {
		sock := testSocket(t)
		win, err := startPipeWindow(realWindow(sock), dialogRequest{Attempt: 1, MaxAttempts: 5, DeferralsLeft: 2, TimeoutSeconds: 60}, sock, os.Getuid())
		if err != nil {
			t.Fatal(err)
		}
		defer win.close()
		if ev, err := win.next(ctx); err != nil || ev.kind != eventShown {
			t.Fatalf("first event = (%+v, %v), want shown", ev, err)
		}
		for _, view := range []string{viewWorking, viewDone} {
			time.Sleep(700 * time.Millisecond)
			if err := win.show(view); err != nil {
				t.Fatalf("show(%s) failed: %v", view, err)
			}
		}
		start := time.Now()
		if _, err := win.next(ctx); !errors.Is(err, io.EOF) {
			t.Fatalf("after the result view: %v, want the end of the window", err)
		}
		if waited := time.Since(start); waited < 10*time.Second || waited > 20*time.Second {
			t.Errorf("the window closed %s after the result view, want about 15 s", waited)
		}
	})

	t.Run("refuses a request that is not JSON", func(t *testing.T) {
		cmd := exec.Command(bin)
		cmd.Stdin = strings.NewReader("--title phishing\n")
		out, err := cmd.Output()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 2 || len(out) != 0 {
			t.Errorf("got err=%v out=%q, want exit status 2 and no output", err, out)
		}
	})
}

func wrongFive() []any {
	var events []any
	for i := 0; i < maxPasswordAttempts; i++ {
		events = append(events, typed("wrong"))
	}
	return events
}

func streakState(streak, unanswered int) string {
	return streakStateWithDeferrals(streak, unanswered, maxDeferrals)
}

func streakStateWithDeferrals(streak, unanswered, deferrals int) string {
	first := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	return fmt.Sprintf(`{"user":"alice","first_prompt":"%s","deferrals":%d,"unanswered":%d,"wrong_password_runs":%d}`, first, deferrals, unanswered, streak)
}

func TestWrongPasswordRunsCountAcrossPrompts(t *testing.T) {
	m, _, _ := dialogManager(t, &fakeWindow{events: wrongFive()}, nil, "correct horse")

	if _, outcome := ask(m, context.Background(), false); outcome != passwordFailed {
		t.Fatalf("first run: got %v, want passwordFailed", outcome)
	}
	if st := readState(t, m); st.WrongPasswordRuns != 1 {
		t.Fatalf("streak after the first run = %d, want 1", st.WrongPasswordRuns)
	}

	win := &fakeWindow{events: wrongFive()}
	m.openWindow = func(context.Context, string, string, dialogRequest) (passwordWindow, error) { return win, nil }
	_, outcome, streak := askWithStreak(m, context.Background())
	if outcome != passwordFailed || streak != 2 {
		t.Fatalf("second run: got (%v, streak %d), want (passwordFailed, 2)", outcome, streak)
	}
	if st := readState(t, m); st.WrongPasswordRuns != 2 {
		t.Errorf("streak on disk after the second run = %d, want 2: the count must survive the run", st.WrongPasswordRuns)
	}
}

func askWithStreak(m *MacOSManager, ctx context.Context) (string, passwordOutcome, int) {
	var got string
	outcome, tally := m.askPassword(ctx, "501", "alice", false, func(_ context.Context, password string) error {
		got = password
		return nil
	})
	return got, outcome, tally.wrongPasswordRuns
}

func TestWrongPasswordRunsResetOnGrant(t *testing.T) {
	m, _, _ := dialogManager(t, &fakeWindow{events: []any{typed("correct horse")}}, nil, "correct horse")
	writeState(t, m, streakState(3, 0))

	_, outcome, streak := askWithStreak(m, context.Background())

	if outcome != passwordOK || streak != 0 {
		t.Fatalf("got (%v, streak %d), want (passwordOK, 0)", outcome, streak)
	}
	if _, err := os.Stat(m.promptStatePath); !os.IsNotExist(err) {
		t.Error("the record stayed after the grant: the streak must start at zero on the next prompt")
	}
}

func TestWrongPasswordRunsStayOnOtherOutcomes(t *testing.T) {
	cases := []struct {
		name   string
		events []any
	}{
		{"later", []any{dialogEvent{kind: eventLater}}},
		{"timeout", []any{dialogEvent{kind: eventTimeout}}},
		{"window ended", []any{io.EOF}},
		{"four wrong passwords and a timeout", append(wrongFive()[:maxPasswordAttempts-1], dialogEvent{kind: eventTimeout})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, _, _ := dialogManager(t, &fakeWindow{events: tc.events}, nil, "correct horse")
			writeState(t, m, streakState(3, 0))

			_, outcome, streak := askWithStreak(m, context.Background())

			if outcome == passwordFailed || outcome == passwordOK {
				t.Fatalf("outcome = %v, the case must end without a verdict on the password", outcome)
			}
			if streak != 3 {
				t.Errorf("reported streak = %d, want 3: a prompt without five wrong passwords changes nothing", streak)
			}
			if st := readState(t, m); st.WrongPasswordRuns != 3 {
				t.Errorf("streak on disk = %d, want 3", st.WrongPasswordRuns)
			}
		})
	}
}

func TestWrongPasswordRunsNegativeStartsFresh(t *testing.T) {
	m, _, _ := dialogManager(t, &fakeWindow{events: []any{dialogEvent{kind: eventTimeout}}}, nil, "correct horse")
	writeState(t, m, streakState(-1, 0))

	ask(m, context.Background(), false)

	if st := readState(t, m); st.WrongPasswordRuns != 0 || st.Deferrals != 0 {
		t.Errorf("state = %+v, want a fresh record: a negative streak is not plausible", st)
	}
}

func TestWrongPasswordPauseFromTheFifthRun(t *testing.T) {
	cases := []struct {
		name       string
		state      string
		pause      time.Duration
		budget     time.Duration // zero means no deadline
		events     []any
		wantPauses []int
		wantViews  []string
		wantOut    passwordOutcome
		wantHelper int
	}{
		{
			name:       "the fifth run pauses and the user gets five attempts again",
			state:      streakState(4, blockScreenAfter),
			events:     append(wrongFive(), typed("correct horse")),
			wantPauses: []int{0},
			wantViews:  []string{viewPassword, viewWorking, viewDone},
			wantOut:    passwordOK,
			wantHelper: maxPasswordAttempts + 1,
		},
		{
			name:       "a spent deferral budget without the screen block pauses as well",
			state:      streakState(4, 0),
			events:     append(wrongFive(), typed("correct horse")),
			wantPauses: []int{0},
			wantViews:  []string{viewPassword, viewWorking, viewDone},
			wantOut:    passwordOK,
			wantHelper: maxPasswordAttempts + 1,
		},
		{
			name:       "the pause waits for the clock and not for the user",
			state:      streakState(4, blockScreenAfter),
			pause:      20 * time.Millisecond,
			events:     append(wrongFive(), func(ctx context.Context) (dialogEvent, error) { <-ctx.Done(); return dialogEvent{}, ctx.Err() }, typed("correct horse")),
			wantPauses: []int{0},
			wantViews:  []string{viewPassword, viewWorking, viewDone},
			wantOut:    passwordOK,
			wantHelper: maxPasswordAttempts + 1,
		},
		{
			name:       "a short run budget closes the window as before",
			state:      streakState(4, blockScreenAfter),
			pause:      20 * time.Second,
			budget:     60 * time.Second,
			events:     append(wrongFive(), typed("correct horse")),
			wantPauses: nil,
			wantViews:  []string{viewFailed},
			wantOut:    passwordFailed,
			wantHelper: maxPasswordAttempts,
		},
		{
			name:       "the fourth run closes the window",
			state:      streakState(3, blockScreenAfter),
			events:     append(wrongFive(), typed("correct horse")),
			wantPauses: nil,
			wantViews:  []string{viewFailed},
			wantOut:    passwordFailed,
			wantHelper: maxPasswordAttempts,
		},
		{
			name:       "with deferrals left and no screen block the window closes",
			state:      streakStateWithDeferrals(4, 0, 0),
			events:     append(wrongFive(), typed("correct horse")),
			wantPauses: nil,
			wantViews:  []string{viewFailed},
			wantOut:    passwordFailed,
			wantHelper: maxPasswordAttempts,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			win := &fakeWindow{events: tc.events}
			m, f, _ := dialogManager(t, win, nil, "correct horse")
			adminAfter(f, 1)
			m.wrongPasswordPause = tc.pause
			writeState(t, m, tc.state)
			ctx, cancel := context.Background(), context.CancelFunc(func() {})
			if tc.budget > 0 {
				ctx, cancel = context.WithTimeout(ctx, tc.budget)
			}
			defer cancel()

			var outcome passwordOutcome
			logged := captureLog(func() { _, outcome, _ = askWithStreak(m, ctx) })

			if outcome != tc.wantOut {
				t.Fatalf("outcome = %v, want %v; log: %s", outcome, tc.wantOut, logged)
			}
			if !reflect.DeepEqual(win.pauses, tc.wantPauses) {
				t.Errorf("pauses = %v, want %v", win.pauses, tc.wantPauses)
			}
			if !reflect.DeepEqual(win.views, tc.wantViews) {
				t.Errorf("views = %v, want %v", win.views, tc.wantViews)
			}
			if n := f.count("mac_helper"); n != tc.wantHelper {
				t.Errorf("helper ran %d time(s), want %d", n, tc.wantHelper)
			}
			if len(tc.wantPauses) > 0 {
				if !reflect.DeepEqual(win.wrongs, []int{2, 3, 4, 5}) {
					t.Errorf("wrongs = %v, want [2 3 4 5]: the sixth password is the first attempt after the pause", win.wrongs)
				}
				if !strings.Contains(logged, "[WRONG PASSWORD PAUSE] alice entered a wrong password in each of 5 attempts.") {
					t.Errorf("the pause has no log line: %s", logged)
				}
			}
			if win.closed == 0 {
				t.Error("the window stayed open")
			}
		})
	}
}

func TestWrongPasswordPauseHappensOncePerRun(t *testing.T) {
	blocker := func(ctx context.Context) (dialogEvent, error) { <-ctx.Done(); return dialogEvent{}, ctx.Err() }
	events := append(wrongFive(), blocker)
	events = append(events, wrongFive()...)
	events = append(events, typed("correct horse"))
	win := &fakeWindow{events: events}
	m, f, _ := dialogManager(t, win, nil, "correct horse")
	adminAfter(f, 1)
	m.wrongPasswordPause = 20 * time.Millisecond
	writeState(t, m, streakState(4, blockScreenAfter))

	var outcome passwordOutcome
	logged := captureLog(func() { _, outcome, _ = askWithStreak(m, context.Background()) })

	if outcome != passwordFailed {
		t.Fatalf("outcome = %v, want passwordFailed: the second batch of wrong passwords ends the prompt; log: %s", outcome, logged)
	}
	if !reflect.DeepEqual(win.pauses, []int{0}) {
		t.Errorf("pauses = %v, want one pause", win.pauses)
	}
	if n := f.count("mac_helper"); n != 2*maxPasswordAttempts {
		t.Errorf("helper ran %d time(s), want %d: ten checks of the console user in one run at most", n, 2*maxPasswordAttempts)
	}
	if got := win.views[len(win.views)-1]; got != viewFailed {
		t.Errorf("last view = %q, want %q", got, viewFailed)
	}
}

func TestWrongPasswordPauseSendsTheSeconds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wait := func(ctx context.Context) (dialogEvent, error) {
		cancel()
		<-ctx.Done()
		return dialogEvent{}, ctx.Err()
	}
	win := &fakeWindow{events: append(wrongFive(), wait, typed("correct horse"))}
	m, f, _ := dialogManager(t, win, nil, "correct horse")
	adminAfter(f, 1)
	m.wrongPasswordPause = 10 * time.Minute
	writeState(t, m, streakState(4, blockScreenAfter))

	_, outcome, _ := askWithStreak(m, ctx)

	if outcome != passwordTimeout {
		t.Fatalf("outcome = %v, want the budget-ended timeout after the cancel", outcome)
	}
	if !reflect.DeepEqual(win.pauses, []int{600}) {
		t.Errorf("pauses = %v, want [600]: the window shows the countdown from the seconds that Go sends", win.pauses)
	}
}

func TestWrongPasswordPauseKeepsTheOtherAnswers(t *testing.T) {
	wait := func(ctx context.Context) (dialogEvent, error) { <-ctx.Done(); return dialogEvent{}, ctx.Err() }
	cases := []struct {
		name    string
		events  []any
		wantOut passwordOutcome
		wantStr int
	}{
		{"timeout during the pause", append(wrongFive(), dialogEvent{kind: eventTimeout}), passwordTimeout, 4},
		{"later during the pause", append(wrongFive(), dialogEvent{kind: eventLater}), passwordTimeout, 4},
		{"the window ended during the pause", append(wrongFive(), io.EOF), passwordUnavailable, 4},
		{"a password during the pause is dropped and the field locks again", append(wrongFive(), typed("correct horse"), wait, typed("correct horse")), passwordOK, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			win := &fakeWindow{events: tc.events}
			m, f, _ := dialogManager(t, win, nil, "correct horse")
			adminAfter(f, 1)
			m.wrongPasswordPause = 20 * time.Millisecond
			writeState(t, m, streakState(4, blockScreenAfter))

			var outcome passwordOutcome
			var streak int
			logged := captureLog(func() { _, outcome, streak = askWithStreak(m, context.Background()) })

			if outcome != tc.wantOut || streak != tc.wantStr {
				t.Fatalf("got (%v, streak %d), want (%v, %d)", outcome, streak, tc.wantOut, tc.wantStr)
			}
			wantPauses := 1
			if strings.Contains(tc.name, "locks again") {
				wantPauses = 2
				if !strings.Contains(logged, "typed a password during the pause") {
					t.Errorf("the dropped password left no trace in the log: %s", logged)
				}
			}
			if len(win.pauses) != wantPauses {
				t.Errorf("pauses = %v, want %d", win.pauses, wantPauses)
			}
		})
	}
}

func TestPauseEndLogsEachStage(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	jump := func(ctx context.Context) (dialogEvent, error) {
		<-ctx.Done()
		clock.t = clock.t.Add(time.Hour)
		return dialogEvent{}, ctx.Err()
	}
	win := &fakeWindow{events: append(wrongFive(), jump, typed("correct horse"))}
	m, f := pausedRun(t, win, clock, 10*time.Millisecond)
	adminAfter(f, 1)

	logged := captureLog(func() { askWithStreak(m, context.Background()) })

	for _, line := range []string{
		"[INFO] The pause of alice ended by the wall clock after 10m0s.",
		"[INFO] alice still holds the administrator session after the pause.",
		"[INFO] The password field of alice is open again; 5 attempts.",
	} {
		if !strings.Contains(logged, line) {
			t.Errorf("missing stage line %q in: %s", line, logged)
		}
	}
}

func adminSequence(f *fakeRunner, members ...bool) {
	inner := f.handle
	checks := 0
	f.handle = func(c call) ([]byte, error) {
		if c.is("dseditgroup", "-o", "checkmember", "-m", "alice", "admin") {
			i := checks
			if i >= len(members) {
				i = len(members) - 1
			}
			checks++
			if members[i] {
				return []byte("yes alice is a member of admin"), nil
			}
			return []byte("no alice is NOT a member of admin"), fakeExit{1}
		}
		return inner(c)
	}
}

func TestAdminSessionIsCheckedBeforeEachPassword(t *testing.T) {
	win := &fakeWindow{events: []any{typed("typo"), typed("stale try"), context.DeadlineExceeded, typed("correct horse")}}
	m, f, _ := dialogManager(t, win, nil, "correct horse")
	adminSequence(f, true, false, true)

	var got string
	var outcome passwordOutcome
	logged := captureLog(func() { got, outcome = ask(m, context.Background(), false) })

	if outcome != passwordOK || got != "correct horse" {
		t.Fatalf("got (%q, %v), want the correct password and passwordOK; log: %s", got, outcome, logged)
	}
	if want := []string{viewAdmin, viewPassword, viewWorking, viewDone}; !reflect.DeepEqual(win.views, want) {
		t.Errorf("views = %v, want %v", win.views, want)
	}
	if n := f.count("mac_helper"); n != 2 {
		t.Errorf("helper calls = %d, want 2: the password typed without admin rights must not be checked", n)
	}
	if !reflect.DeepEqual(win.wrongs, []int{2}) {
		t.Errorf("wrong commands = %v, want [2]: the attempt without admin rights must not be consumed", win.wrongs)
	}
	if !strings.Contains(logged, "lost the administrator session") {
		t.Errorf("no log line for the lost session: %s", logged)
	}
}

func TestAdminSessionIsCheckedBeforeEachAttemptAfterThePause(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	jump := func(ctx context.Context) (dialogEvent, error) {
		<-ctx.Done()
		clock.t = clock.t.Add(time.Hour)
		return dialogEvent{}, ctx.Err()
	}
	win := &fakeWindow{events: append(wrongFive(), jump, typed("stale try"), context.DeadlineExceeded, typed("correct horse"))}
	m, f := pausedRun(t, win, clock, 10*time.Millisecond)
	adminSequence(f, true, true, true, true, true, true, false, true)

	var outcome passwordOutcome
	logged := captureLog(func() { _, outcome, _ = askWithStreak(m, context.Background()) })

	if outcome != passwordOK {
		t.Fatalf("outcome = %v, want passwordOK; log: %s", outcome, logged)
	}
	want := []string{viewPassword, viewAdmin, viewPassword, viewWorking, viewDone}
	if !reflect.DeepEqual(win.views, want) {
		t.Errorf("views = %v, want %v", win.views, want)
	}
	if n := f.count("mac_helper"); n != maxPasswordAttempts+1 {
		t.Errorf("helper calls = %d, want %d: the password typed without admin rights must not be checked", n, maxPasswordAttempts+1)
	}
	if len(win.wrongs) != maxPasswordAttempts-1 {
		t.Errorf("wrong commands = %v: the attempt without admin rights must not be consumed", win.wrongs)
	}
	if !strings.Contains(logged, "lost the administrator session") {
		t.Errorf("no log line for the lost session: %s", logged)
	}
}

func TestWindowFailedRunsCountAndReset(t *testing.T) {
	m, _, _ := dialogManager(t, &fakeWindow{events: []any{io.EOF}}, nil, "correct horse")

	outcome, tally := m.askPassword(context.Background(), "501", "alice", false, func(context.Context, string) error { return nil })
	if outcome != passwordUnavailable || !tally.windowFailed || tally.windowFailedRuns != 1 {
		t.Fatalf("first run: got (%v, %+v), want (passwordUnavailable, windowFailed 1)", outcome, tally)
	}
	if st := readState(t, m); st.WindowFailedRuns != 1 || st.WrongPasswordRuns != 0 {
		t.Fatalf("state after the first run = %+v", st)
	}

	m.openWindow = func(context.Context, string, string, dialogRequest) (passwordWindow, error) {
		return &fakeWindow{events: []any{dialogEvent{kind: eventLater}}}, nil
	}
	if _, tally := m.askPassword(context.Background(), "501", "alice", false, nil); tally.windowFailed || tally.windowFailedRuns != 1 {
		t.Fatalf("a postponement changed the streak: %+v", tally)
	}

	for name, events := range map[string][]any{"a timeout": {dialogEvent{kind: eventTimeout}}, "five wrong passwords": wrongFive()} {
		m.openWindow = func(context.Context, string, string, dialogRequest) (passwordWindow, error) {
			return &fakeWindow{events: events}, nil
		}
		if _, tally := m.askPassword(context.Background(), "501", "alice", false, nil); tally.windowFailed || tally.windowFailedRuns != 1 {
			t.Fatalf("%s changed the streak: %+v", name, tally)
		}
	}

	m.openWindow = func(context.Context, string, string, dialogRequest) (passwordWindow, error) {
		return &fakeWindow{events: []any{errors.New("signal: terminated")}}, nil
	}
	if _, tally := m.askPassword(context.Background(), "501", "alice", false, nil); !tally.windowFailed || tally.windowFailedRuns != 2 {
		t.Fatalf("second window end: %+v, want windowFailed 2", tally)
	}

	m.openWindow = func(context.Context, string, string, dialogRequest) (passwordWindow, error) {
		return &fakeWindow{events: []any{typed("correct horse")}}, nil
	}
	outcome, tally = m.askPassword(context.Background(), "501", "alice", false, func(context.Context, string) error { return nil })
	if outcome != passwordOK || tally.windowFailedRuns != 0 {
		t.Fatalf("grant: got (%v, %+v), want (passwordOK, 0)", outcome, tally)
	}
	if _, err := os.Stat(m.promptStatePath); !os.IsNotExist(err) {
		t.Error("the record stayed after the grant")
	}
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func pausedRun(t *testing.T, win *fakeWindow, clock *fakeClock, tick time.Duration) (*MacOSManager, *fakeRunner) {
	t.Helper()
	m, f, _ := dialogManager(t, win, nil, "correct horse")
	writeState(t, m, streakState(4, blockScreenAfter))
	m.now = clock.now
	m.wrongPasswordPause = 10 * time.Minute
	m.pauseTick = tick
	return m, f
}

func TestWrongPasswordPauseEndsByTheWallClock(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	jump := func(ctx context.Context) (dialogEvent, error) {
		<-ctx.Done()
		clock.t = clock.t.Add(time.Hour)
		return dialogEvent{}, ctx.Err()
	}
	win := &fakeWindow{events: append(wrongFive(), jump, typed("correct horse"))}
	m, f := pausedRun(t, win, clock, 10*time.Millisecond)
	adminAfter(f, 1)

	done := make(chan passwordOutcome, 1)
	go func() { _, outcome, _ := askWithStreak(m, context.Background()); done <- outcome }()
	select {
	case outcome := <-done:
		if outcome != passwordOK {
			t.Fatalf("outcome = %v, want passwordOK", outcome)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the pause did not end when the wall clock passed its end")
	}
	if !reflect.DeepEqual(win.pauses, []int{600}) {
		t.Errorf("pauses = %v, want [600]", win.pauses)
	}
	if !reflect.DeepEqual(win.views, []string{viewPassword, viewWorking, viewDone}) {
		t.Errorf("views = %v, want the password step after the pause", win.views)
	}
}

func TestWrongPasswordPauseWaitsForTheWallClock(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	win := &fakeWindow{}
	ticks := 0
	var tick func(ctx context.Context) (dialogEvent, error)
	tick = func(ctx context.Context) (dialogEvent, error) {
		if len(win.views) > 0 {
			return dialogEvent{kind: eventLater}, nil
		}
		<-ctx.Done()
		ticks++
		if ticks < 8 {
			win.events = append([]any{tick}, win.events...)
			return dialogEvent{}, ctx.Err()
		}
		return dialogEvent{kind: eventLater}, nil
	}
	win.events = append(wrongFive(), tick)
	m, f := pausedRun(t, win, clock, 5*time.Millisecond)
	adminAfter(f, 1)
	m.wrongPasswordPause = 20 * time.Millisecond

	_, outcome, _ := askWithStreak(m, context.Background())

	if outcome != passwordTimeout {
		t.Fatalf("outcome = %v, want the timeout of a Later without a postponement", outcome)
	}
	if ticks != 8 {
		t.Errorf("ticks = %d, want 8", ticks)
	}
	if len(win.views) != 0 {
		t.Errorf("views = %v, want none: the pause must not end while the clock stands still", win.views)
	}
}

func TestAdminSessionIsCheckedAgainAfterThePause(t *testing.T) {
	cases := []struct {
		name       string
		members    []bool
		events     []any
		wantViews  []string
		wantChecks int
	}{
		{
			name:       "the session ended during the pause",
			members:    []bool{true, true, true, true, true, false, true},
			events:     []any{context.DeadlineExceeded, typed("correct horse")},
			wantViews:  []string{viewAdmin, viewPassword, viewWorking, viewDone},
			wantChecks: 8,
		},
		{
			name:       "the session is still there",
			members:    []bool{true},
			events:     []any{typed("correct horse")},
			wantViews:  []string{viewPassword, viewWorking, viewDone},
			wantChecks: 7,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clock := &fakeClock{t: time.Now()}
			jump := func(ctx context.Context) (dialogEvent, error) {
				<-ctx.Done()
				clock.t = clock.t.Add(time.Hour)
				return dialogEvent{}, ctx.Err()
			}
			win := &fakeWindow{events: append(append(wrongFive(), jump), tc.events...)}
			m, f := pausedRun(t, win, clock, 10*time.Millisecond)
			adminSequence(f, tc.members...)

			var outcome passwordOutcome
			logged := captureLog(func() { _, outcome, _ = askWithStreak(m, context.Background()) })

			if outcome != passwordOK {
				t.Fatalf("outcome = %v, want passwordOK; log: %s", outcome, logged)
			}
			if !reflect.DeepEqual(win.views, tc.wantViews) {
				t.Errorf("views = %v, want %v", win.views, tc.wantViews)
			}
			if n := f.count("dseditgroup"); n != tc.wantChecks {
				t.Errorf("admin group checks = %d, want %d", n, tc.wantChecks)
			}
			lost := strings.Contains(logged, "[INFO] alice lost the administrator session during the pause; asking for Admin By Request again.")
			wantLost := len(tc.members) > 1
			if lost != wantLost {
				t.Errorf("lost-session log line present = %v, want %v: %s", lost, wantLost, logged)
			}
		})
	}
}
