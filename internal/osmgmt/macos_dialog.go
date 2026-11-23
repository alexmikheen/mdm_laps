// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

//go:build darwin

package osmgmt

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	authWindowPath      = "/usr/local/bin/golaps_auth"
	maxPasswordAttempts = 5

	// Escalation thresholds for consecutive wrong-password or killed-window runs.
	wrongPasswordRedAfter   = 2
	wrongPasswordPauseAfter = 4
	windowFailedRedAfter    = 2
	wrongPasswordPause      = 10 * time.Minute

	// Poll wall-clock time during pauses because Go monotonic timers freeze while macOS sleeps.
	pauseTick = 5 * time.Second

	helpArticleURL   = ""
	maxDeferrals     = 3
	deferralWindow   = 7 * 24 * time.Hour
	blockScreenAfter = 7
	backdropPath     = "/usr/local/golaps/backdrop.jpg"
	promptStatePath  = "/var/db/golaps/token_prompt.json"
	windowStartGrace = 20 * time.Second
	minPromptTime    = 30 * time.Second

	// Passwords travel only over this root-owned Unix socket, never over stdout.
	authSocketPath    = "/var/run/golaps_auth.sock"
	maxWindowLine     = 64 * 1024
	windowAnswerGrace = 15 * time.Second
	resultLinger      = 20 * time.Second
	windowCloseGrace  = 3 * time.Second
)

type passwordOutcome int

const (
	passwordOK passwordOutcome = iota
	passwordLater
	passwordFailed
	passwordTimeout
	passwordUnavailable
	passwordGrantFailed
)

// Stable PROMPT report tokens parsed by MDM reporting.
const (
	reportOK            = "ok"
	reportLater         = "later"
	reportTimeout       = "timeout"
	reportWrongPassword = "wrong-password"
	reportGrantFailed   = "grant-failed"
	reportWindowFailed  = "window-failed"
	reportLocked        = "skipped-screen-locked"
	reportNoTime        = "skipped-no-time"
	reportBudgetEnded   = "budget-ended"
	reportNoUser        = "no-console-user"
	reportUserNoToken   = "user-has-no-token"
	reportNoAbR         = "no-admin-by-request"
)

func promptReport(outcome passwordOutcome, word string) string {
	if word != "" {
		return word
	}
	switch outcome {
	case passwordOK:
		return reportOK
	case passwordLater:
		return reportLater
	case passwordFailed:
		return reportWrongPassword
	case passwordTimeout:
		return reportTimeout
	case passwordGrantFailed:
		return reportGrantFailed
	}
	return reportWindowFailed
}

func logPromptReport(word string) {
	log.Printf("PROMPT: %s\n", word)
}

const (
	viewAdmin    = "admin"
	viewPassword = "password"
	viewWorking  = "working"
	viewDone     = "done"
	viewError    = "error"
	viewFailed   = "failed"
	viewPaused   = "paused"
)

func (o passwordOutcome) String() string {
	switch o {
	case passwordOK:
		return "ok"
	case passwordLater:
		return "later"
	case passwordFailed:
		return "failed"
	case passwordTimeout:
		return "timeout"
	case passwordUnavailable:
		return "unavailable"
	case passwordGrantFailed:
		return "grant-failed"
	}
	return fmt.Sprintf("passwordOutcome(%d)", int(o))
}

// dialogRequest carries only numbers and flags so the user-session window never renders untrusted text.
type dialogRequest struct {
	Attempt        int  `json:"attempt"`
	MaxAttempts    int  `json:"maxAttempts"`
	DeferralsLeft  int  `json:"deferralsLeft"`
	BlockScreen    bool `json:"blockScreen"`
	NeedAdmin      bool `json:"needAdmin"`
	TimeoutSeconds int  `json:"timeoutSeconds"`
}

type dialogCommand struct {
	Cmd     string `json:"cmd"`
	Attempt int    `json:"attempt,omitempty"`
	View    string `json:"view,omitempty"`
	Seconds int    `json:"seconds,omitempty"`
}

type dialogEventKind int

const (
	eventPassword dialogEventKind = iota + 1
	eventLater
	eventTimeout
	eventShown
	eventAdminRequested
)

type dialogEvent struct {
	kind     dialogEventKind
	password string
}

// parseDialogEvent parses untrusted stdout lines from the window and rejects any password field.
func parseDialogEvent(line string) (dialogEvent, error) {
	var raw struct {
		Event    string `json:"event"`
		Password string `json:"password"`
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(line)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return dialogEvent{}, errors.New("the window sent a line that is not a known answer")
	}
	switch {
	case raw.Event == "password" || raw.Password != "":
		// The password comes through the socket only. A password on the output is a window that is not ours, or an old one.
		return dialogEvent{}, errors.New("the window sent a password on its output")
	case raw.Event == "later" && raw.Password == "":
		return dialogEvent{kind: eventLater}, nil
	case raw.Event == "timeout" && raw.Password == "":
		return dialogEvent{kind: eventTimeout}, nil
	case raw.Event == "shown" && raw.Password == "":
		return dialogEvent{kind: eventShown}, nil
	case raw.Event == "abr" && raw.Password == "":
		return dialogEvent{kind: eventAdminRequested}, nil
	}
	return dialogEvent{}, errors.New("the window sent an answer that is not later, timeout, shown or abr")
}

type promptState struct {
	User              string    `json:"user"`
	FirstPrompt       time.Time `json:"first_prompt"`
	Deferrals         int       `json:"deferrals"`
	Unanswered        int       `json:"unanswered"`
	WrongPasswordRuns int       `json:"wrong_password_runs"`
	WindowFailedRuns  int       `json:"window_failed_runs"`
}

type promptTally struct {
	wrongPasswordRuns int
	windowFailedRuns  int
	windowFailed      bool
}

func (s promptState) deferralsLeft(now time.Time) int {
	if now.Sub(s.FirstPrompt) >= deferralWindow || s.Deferrals >= maxDeferrals {
		return 0
	}
	return maxDeferrals - s.Deferrals
}

func (m *MacOSManager) loadPromptState(user string) promptState {
	fresh := promptState{User: user, FirstPrompt: m.now().UTC()}
	if m.promptStatePath == "" {
		return fresh
	}
	raw, err := os.ReadFile(m.promptStatePath)
	if err != nil {
		return fresh
	}
	var state promptState
	if err := json.Unmarshal(raw, &state); err != nil {
		log.Printf("[WARNING] The deferral record %s is not readable (%v). Starting a new budget for %s.\n", m.promptStatePath, err, user)
		return fresh
	}
	if state.User != user {
		// A shared Mac must not hand the spent budget of one person to the next one.
		return fresh
	}
	if state.FirstPrompt.IsZero() || state.FirstPrompt.After(m.now()) || state.Deferrals < 0 || state.Unanswered < 0 || state.WrongPasswordRuns < 0 || state.WindowFailedRuns < 0 {
		log.Printf("[WARNING] The deferral record of %s is not plausible (first prompt %s, %d postponements). Starting a new budget.\n", user, state.FirstPrompt.Format(time.RFC3339), state.Deferrals)
		return fresh
	}
	return state
}

func (m *MacOSManager) savePromptState(state promptState) {
	if m.promptStatePath == "" {
		return
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(m.promptStatePath), 0o700); err != nil {
		log.Printf("[WARNING] Could not create the directory of the deferral record: %v\n", err)
		return
	}
	// Atomic write so an interrupted run preserves the previous state file.
	tmp := m.promptStatePath + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		log.Printf("[WARNING] Could not write the deferral record: %v\n", err)
		return
	}
	if err := os.Rename(tmp, m.promptStatePath); err != nil {
		log.Printf("[WARNING] Could not replace the deferral record: %v\n", err)
		os.Remove(tmp)
	}
}

func (m *MacOSManager) countUnanswered(state *promptState) {
	state.Unanswered++
	m.savePromptState(*state)
}

func (m *MacOSManager) countWrongPasswordRun(state *promptState) {
	state.WrongPasswordRuns++
	m.savePromptState(*state)
}

func (m *MacOSManager) clearPromptState() {
	if m.promptStatePath == "" {
		return
	}
	if err := os.Remove(m.promptStatePath); err != nil && !os.IsNotExist(err) {
		log.Printf("[WARNING] Could not remove the deferral record: %v\n", err)
	}
}

type passwordWindow interface {
	next(ctx context.Context) (dialogEvent, error)
	wrong(attempt int) error
	show(view string) error
	pause(seconds int) error
	close()
}

type windowMessage struct {
	event dialogEvent
	err   error
}

type pipeWindow struct {
	cmd        *exec.Cmd
	stdin      io.WriteCloser
	messages   chan windowMessage
	quit       chan struct{}
	readerDone chan struct{}
	closeOnce  sync.Once
	socket     *net.UnixListener
	socketPath string
	socketDone chan struct{}
	peerUID    int
}

// startPipeWindow binds the password socket, starts cmd, and sends the initial request.
func startPipeWindow(cmd *exec.Cmd, req dialogRequest, socketPath string, uid int) (*pipeWindow, error) {
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("could not remove the old password socket: %w", err)
	}
	// Set socket mode 0666 via umask before bind to avoid a post-bind chmod race in /var/run.
	oldMask := unix.Umask(0o111)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	unix.Umask(oldMask)
	if err != nil {
		return nil, fmt.Errorf("could not open the password socket: %w", err)
	}
	fail := func(err error) (*pipeWindow, error) {
		listener.Close()
		os.Remove(socketPath)
		return nil, err
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fail(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fail(err)
	}
	if err := cmd.Start(); err != nil {
		return fail(fmt.Errorf("could not start the password window: %w", err))
	}
	w := &pipeWindow{
		cmd:        cmd,
		stdin:      stdin,
		messages:   make(chan windowMessage),
		quit:       make(chan struct{}),
		readerDone: make(chan struct{}),
		socket:     listener,
		socketPath: socketPath,
		socketDone: make(chan struct{}),
		peerUID:    uid,
	}
	go w.read(stdout)
	go w.acceptPasswords()
	if err := w.send(req); err != nil {
		w.close()
		return nil, fmt.Errorf("could not send the request to the password window: %w", err)
	}
	return w, nil
}

func (w *pipeWindow) acceptPasswords() {
	defer close(w.socketDone)
	for {
		conn, err := w.socket.AcceptUnix()
		if err != nil {
			return // the listener is closed
		}
		password, ok := w.readPassword(conn)
		conn.Close()
		if ok {
			w.deliver(windowMessage{event: dialogEvent{kind: eventPassword, password: password}})
		}
	}
}

func (w *pipeWindow) readPassword(conn *net.UnixConn) (string, bool) {
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if uid, err := peerUID(conn); err != nil || uid != w.peerUID {
		log.Printf("[WARNING] Dropped a connection to the password socket that is not from the console user (uid %d, err %v).\n", uid, err)
		return "", false
	}
	line, err := bufio.NewReader(io.LimitReader(conn, maxWindowLine+1)).ReadString('\n')
	if err != nil {
		// PasswordChannel.reachable opens and closes an empty connection at startup.
		if errors.Is(err, io.EOF) && line == "" {
			log.Printf("[INFO] The window checked that the password socket is reachable.\n")
			return "", false
		}
		log.Printf("[WARNING] A connection to the password socket ended before a full line arrived (%v). The window must send the password again.\n", err)
		return "", false
	}
	if len(line) > maxWindowLine {
		log.Printf("[WARNING] A line on the password socket is longer than %d bytes. It is dropped.\n", maxWindowLine)
		return "", false
	}
	password := strings.TrimSuffix(line, "\n")
	if password == "" {
		log.Printf("[WARNING] The password socket received an empty line. It is dropped.\n")
		return "", false
	}
	return password, true
}

// peerUID returns the effective uid of the process at the other end of a unix socket.
func peerUID(conn *net.UnixConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return -1, err
	}
	uid := -1
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		var cred *unix.Xucred
		cred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if credErr == nil {
			uid = int(cred.Uid)
		}
	}); err != nil {
		return -1, err
	}
	return uid, credErr
}

func (w *pipeWindow) send(v any) error {
	line, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.stdin.Write(append(line, '\n'))
	return err
}

// read parses stdout lines and drains remaining output after close so the child never blocks on a full pipe.
func (w *pipeWindow) read(stdout io.Reader) {
	defer close(w.readerDone)
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 4096), maxWindowLine)
	for scanner.Scan() {
		event, err := parseDialogEvent(scanner.Text())
		w.deliver(windowMessage{event: event, err: err})
	}
	if scanner.Err() != nil {
		w.deliver(windowMessage{err: errors.New("the password window sent a line that is too long")})
		_, _ = io.Copy(io.Discard, stdout)
		return
	}
	w.deliver(windowMessage{err: fmt.Errorf("the password window ended without an answer: %w", io.EOF)})
}

func (w *pipeWindow) deliver(m windowMessage) {
	select {
	case w.messages <- m:
	case <-w.quit:
	}
}

func (w *pipeWindow) next(ctx context.Context) (dialogEvent, error) {
	select {
	case m := <-w.messages:
		return m.event, m.err
	case <-w.readerDone:
		return dialogEvent{}, fmt.Errorf("the password window is gone: %w", io.EOF)
	case <-ctx.Done():
		return dialogEvent{}, ctx.Err()
	}
}

func (w *pipeWindow) wrong(attempt int) error {
	return w.send(dialogCommand{Cmd: "wrong", Attempt: attempt})
}

func (w *pipeWindow) show(view string) error {
	return w.send(dialogCommand{Cmd: "show", View: view})
}

func (w *pipeWindow) pause(seconds int) error {
	return w.send(dialogCommand{Cmd: "show", View: viewPaused, Seconds: seconds})
}

// close shuts down the window via stdin EOF, drains stdout before Wait, and kills the process group on timeout.
func (w *pipeWindow) close() {
	w.closeOnce.Do(func() {
		close(w.quit)
		w.stdin.Close()
		killGroup := func() {
			if w.cmd.Process == nil {
				return
			}
			if w.cmd.SysProcAttr != nil && w.cmd.SysProcAttr.Setpgid && w.cmd.Process.Pid > 0 {
				_ = syscall.Kill(-w.cmd.Process.Pid, syscall.SIGKILL)
				return
			}
			_ = w.cmd.Process.Kill()
		}
		select {
		case <-w.readerDone:
		case <-time.After(windowCloseGrace):
			killGroup()
			<-w.readerDone
		}
		exited := make(chan error, 1)
		go func() { exited <- w.cmd.Wait() }()
		var err error
		select {
		case err = <-exited:
		case <-time.After(windowCloseGrace):
			killGroup()
			err = <-exited
		}
		w.socket.Close()
		<-w.socketDone
		os.Remove(w.socketPath)
		if err != nil {
			log.Printf("[INFO] The password window process did not end normally: %v\n", err)
		}
	})
}

func (m *MacOSManager) openAuthWindow(ctx context.Context, uid, user string, req dialogRequest) (passwordWindow, error) {
	if err := m.trustedBinary(authWindowPath); err != nil {
		return nil, fmt.Errorf("the password window is not installed or not trusted: %w", err)
	}
	numericUID, err := strconv.Atoi(uid)
	if err != nil {
		return nil, fmt.Errorf("the uid of the console user is not a number: %q", uid)
	}
	return startPipeWindow(commandContext(ctx, toolLaunchctl, "asuser", uid, toolSudo, "-u", user, authWindowPath), req, m.authSocketPath, numericUID)
}

var screenLockedRe = regexp.MustCompile(`<key>CGSSessionScreenIsLocked</key>\s*<true/>`)

func sessionLocked(ioregOutput string) bool {
	return screenLockedRe.MatchString(ioregOutput)
}

func (m *MacOSManager) screenLocked(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := m.run.Run(ctx, "", toolIoreg, "-n", "Root", "-d1", "-a")
	return err == nil && sessionLocked(string(out))
}

func promptTime(ctx context.Context) time.Duration {
	limit := dialogWait
	if deadline, ok := ctx.Deadline(); ok {
		if left := time.Until(deadline) - windowAnswerGrace; left < limit {
			limit = left
		}
	}
	return limit
}

func (m *MacOSManager) pauseFits(ctx context.Context, pause time.Duration) bool {
	deadline, ok := ctx.Deadline()
	if !ok {
		return true
	}
	return deadline.Sub(m.now())-pause-windowAnswerGrace >= minPromptTime
}

// askPassword runs the native auth window flow, verifies the password, and invokes use to grant the Secure Token.
func (m *MacOSManager) askPassword(ctx context.Context, uid, user string, needAdmin bool, use func(ctx context.Context, password string) error) (outcome passwordOutcome, tally promptTally) {
	word := ""
	defer func() { logPromptReport(promptReport(outcome, word)) }()

	limit := promptTime(ctx)
	if ctx.Err() != nil || limit < minPromptTime {
		log.Printf("[PROMPT SKIPPED: no-time] The run budget has no time left for the password window of %s. The prompt returns on the next check-in.\n", user)
		word = reportNoTime
		return passwordTimeout, promptTally{}
	}
	if m.screenLocked(ctx) {
		log.Printf("[PROMPT SKIPPED: screen-locked] The screen of %s is locked. The prompt returns on the next check-in.\n", user)
		word = reportLocked
		return passwordTimeout, promptTally{}
	}

	attempt := 1
	state := m.loadPromptState(user)
	windowFailed := false
	counts := func() promptTally {
		return promptTally{wrongPasswordRuns: state.WrongPasswordRuns, windowFailedRuns: state.WindowFailedRuns, windowFailed: windowFailed}
	}
	deferralsLeft := state.deferralsLeft(m.now())
	blockScreen := state.Unanswered >= blockScreenAfter
	// Lock the field for a pause instead of closing once deferrals end and the wrong-password streak reaches wrongPasswordPauseAfter.
	pauseInsteadOfClose := (deferralsLeft == 0 || blockScreen) && state.WrongPasswordRuns >= wrongPasswordPauseAfter
	window, err := m.openWindow(ctx, uid, user, dialogRequest{
		Attempt:        attempt,
		MaxAttempts:    maxPasswordAttempts,
		DeferralsLeft:  deferralsLeft,
		BlockScreen:    blockScreen,
		NeedAdmin:      needAdmin,
		TimeoutSeconds: int(limit / time.Second),
	})
	if err != nil {
		log.Printf("[PROMPT FAILED: window] The window could not start for %s (%v). No prompt in this run.\n", user, err)
		return passwordUnavailable, counts()
	}
	defer window.close()

	// Wait for eventShown before charging the deferral budget.
	startCtx, cancelStart := context.WithTimeout(ctx, windowStartGrace)
	first, err := window.next(startCtx)
	cancelStart()
	if err != nil || first.kind != eventShown {
		log.Printf("[PROMPT FAILED: window] The window did not appear for %s (%v). No prompt in this run.\n", user, err)
		return passwordUnavailable, counts()
	}

	m.savePromptState(state)
	if deferralsLeft == 0 {
		log.Printf("[DEFERRAL LIMIT] %s can no longer postpone the Secure Token grant (%d/%d postponements used, first prompt %s).\n", user, state.Deferrals, maxDeferrals, state.FirstPrompt.Format("2006-01-02"))
	}
	if blockScreen {
		log.Printf("[SCREEN BLOCK] %s did not type the password in %d prompts. The password window covers the screen.\n", user, state.Unanswered)
	}

	broken := func(cause error) passwordOutcome {
		log.Printf("[PROMPT FAILED: window] The window of %s ended before an answer (%v). The prompt returns on the next check-in.\n", user, cause)
		windowFailed = true
		state.WindowFailedRuns++
		m.countUnanswered(&state)
		return passwordUnavailable
	}
	later := func() passwordOutcome {
		if deferralsLeft == 0 {
			log.Printf("[WARNING] The password window of %s reported Later although no postponement is left. Not counted. The prompt returns on the next check-in.\n", user)
			m.countUnanswered(&state)
			return passwordTimeout
		}
		state.Deferrals++
		m.countUnanswered(&state)
		log.Printf("[DEFERRED %d/%d] %s postponed the Secure Token grant. The prompt returns on the next check-in.\n", state.Deferrals, maxDeferrals, user)
		return passwordLater
	}
	timeout := func() passwordOutcome {
		log.Printf("[WARNING] %s did not answer the password window within %s. The prompt returns on the next check-in.\n", user, limit)
		m.countUnanswered(&state)
		return passwordTimeout
	}
	budgetEnded := func() passwordOutcome {
		log.Printf("[WARNING] The run budget ended while the password window of %s was open. The prompt returns on the next check-in.\n", user)
		word = reportBudgetEnded
		return passwordTimeout
	}
	result := func(view string) {
		if window.show(view) != nil {
			return
		}
		lingerCtx, cancel := context.WithTimeout(ctx, resultLinger)
		defer cancel()
		for {
			if _, err := window.next(lingerCtx); err != nil {
				return
			}
		}
	}

	waitAdmin := func() (outcome passwordOutcome, ok bool) {
		waitStart := time.Now()
		for {
			tickCtx, cancel := context.WithTimeout(ctx, abrPollInterval)
			event, err := window.next(tickCtx)
			cancel()
			if err != nil {
				if ctx.Err() != nil {
					return budgetEnded(), false
				}
				if !errors.Is(err, context.DeadlineExceeded) {
					return broken(err), false
				}
				if m.inAdminGroup(ctx, user) {
					log.Printf("[SUCCESS] %s obtained admin rights via Admin By Request. Continuing.\n", user)
					return passwordOK, true
				}
				if time.Since(waitStart) > limit+windowAnswerGrace {
					log.Printf("[WARNING] The password window gave no answer in time (%v). The prompt returns on the next check-in.\n", err)
					m.countUnanswered(&state)
					return passwordTimeout, false
				}
				continue
			}
			switch event.kind {
			case eventShown:
			case eventAdminRequested:
				log.Printf("[WAIT] %s asked for an Admin By Request session; waiting up to %s.\n", user, limit)
				if err := m.openApp(ctx, uid, user, abrAppName); err != nil {
					log.Printf("[WARNING] Admin By Request could not be raised for %s: %v. The user can open it from the menu bar.\n", user, err)
				}
				// The window starts its time limit again at this click. Do the same here.
				waitStart = time.Now()
			case eventLater:
				return later(), false
			case eventTimeout:
				return timeout(), false
			default:
				// A password in the admin step cannot be used: the grant needs the admin rights first. The window sends none in this step.
				return broken(errors.New("the window sent a password before the admin rights were there")), false
			}
		}
	}

	// Lock the password field for wrongPasswordPause by wall clock, then verify admin rights again.
	pause := func() (outcome passwordOutcome, ok bool) {
		log.Printf("[WRONG PASSWORD PAUSE] %s entered a wrong password in each of %d attempts. The password field is locked for %s and the screen stays blocked.\n", user, maxPasswordAttempts, m.wrongPasswordPause)
		if err := window.pause(int(m.wrongPasswordPause / time.Second)); err != nil {
			return broken(err), false
		}
		tick := m.pauseTick
		if tick <= 0 {
			tick = pauseTick
		}
		pauseUntil := m.now().Add(m.wrongPasswordPause)
		for left := pauseUntil.Sub(m.now()); left > 0; left = pauseUntil.Sub(m.now()) {
			tickCtx, cancel := context.WithTimeout(ctx, min(tick, left))
			event, err := window.next(tickCtx)
			cancel()
			if err != nil {
				if ctx.Err() != nil {
					return budgetEnded(), false
				}
				if errors.Is(err, context.DeadlineExceeded) {
					continue
				}
				return broken(err), false
			}
			switch event.kind {
			case eventLater:
				return later(), false
			case eventTimeout:
				return timeout(), false
			case eventPassword:
				// The window opens its field only on the view password, which comes after this loop. If a password arrives early while paused, re-send the pause command so the window stays synchronized.
				log.Printf("[WARNING] %s typed a password during the pause. It is not checked. The field is locked again for the rest of the pause.\n", user)
				if err := window.pause(int(pauseUntil.Sub(m.now()) / time.Second)); err != nil {
					return broken(err), false
				}
			}
		}
		log.Printf("[INFO] The pause of %s ended by the wall clock after %s.\n", user, m.wrongPasswordPause)
		if !m.inAdminGroup(ctx, user) {
			log.Printf("[INFO] %s lost the administrator session during the pause; asking for Admin By Request again.\n", user)
			if err := window.show(viewAdmin); err != nil {
				return broken(err), false
			}
			if outcome, ok := waitAdmin(); !ok {
				return outcome, false
			}
		} else {
			log.Printf("[INFO] %s still holds the administrator session after the pause.\n", user)
		}
		if err := window.show(viewPassword); err != nil {
			return broken(err), false
		}
		log.Printf("[INFO] The password field of %s is open again; %d attempts.\n", user, maxPasswordAttempts)
		return passwordOK, true
	}

	if needAdmin {
		if outcome, ok := waitAdmin(); !ok {
			return outcome, counts()
		}
		if err := window.show(viewPassword); err != nil {
			return broken(err), counts()
		}
	}

	afterPause := false
	for attempt <= maxPasswordAttempts {
		waitCtx, cancel := context.WithTimeout(ctx, limit+windowAnswerGrace)
		event, err := window.next(waitCtx)
		expired := waitCtx.Err() != nil
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return budgetEnded(), counts()
			}
			if expired {
				log.Printf("[WARNING] The password window gave no answer in time (%v). The prompt returns on the next check-in.\n", err)
				m.countUnanswered(&state)
				return passwordTimeout, counts()
			}
			return broken(err), counts()
		}

		switch event.kind {
		case eventShown, eventAdminRequested:
			continue
		case eventLater:
			return later(), counts()
		case eventTimeout:
			return timeout(), counts()
		}

		if afterPause && !m.inAdminGroup(ctx, user) {
			log.Printf("[INFO] %s lost the administrator session after the pause; asking for Admin By Request again before the password is checked.\n", user)
			if err := window.show(viewAdmin); err != nil {
				return broken(err), counts()
			}
			if outcome, ok := waitAdmin(); !ok {
				return outcome, counts()
			}
			if err := window.show(viewPassword); err != nil {
				return broken(err), counts()
			}
			continue
		}

		if !m.verifyUserPassword(ctx, user, event.password) {
			log.Printf("[WARNING] Incorrect password entered in GUI (Attempt %d).\n", attempt)
			attempt++
			if attempt > maxPasswordAttempts {
				if !pauseInsteadOfClose || !m.pauseFits(ctx, m.wrongPasswordPause) {
					break
				}
				if outcome, ok := pause(); !ok {
					return outcome, counts()
				}
				attempt = 1
				afterPause = true
				continue
			}
			if err := window.wrong(attempt); err != nil {
				return broken(err), counts()
			}
			continue
		}

		log.Println("[INFO] Valid GUI password received. Delegating grant to Swift Helper...")
		_ = window.show(viewWorking)
		grantErr := use(ctx, event.password)

		// Retry once if the temporary Admin By Request session expired before the grant ran.
		if grantErr != nil && !m.inAdminGroup(ctx, user) {
			log.Printf("[WARNING] Grant refused because %s is not an administrator (Admin By Request rights expired?). Offering an AbR session and retrying...\n", user)
			if err := window.show(viewAdmin); err != nil {
				return broken(err), counts()
			}
			if outcome, ok := waitAdmin(); !ok {
				return outcome, counts()
			}
			_ = window.show(viewWorking)
			grantErr = use(ctx, event.password)
		}
		if grantErr != nil {
			log.Printf("[ERROR] Swift token grant failed: %v\n", grantErr)
			result(viewError)
			return passwordGrantFailed, counts()
		}
		log.Println("[SUCCESS] GUI Token Grant Successful!")
		// The grant worked, so both streaks end with the record.
		state.WrongPasswordRuns = 0
		state.WindowFailedRuns = 0
		m.clearPromptState()
		result(viewDone)
		return passwordOK, counts()
	}

	// Each attempt was a wrong password. The window tells the user where to get help. The run counts against the streak.
	m.countWrongPasswordRun(&state)
	result(viewFailed)
	return passwordFailed, counts()
}
