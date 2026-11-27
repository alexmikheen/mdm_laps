// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"golaps/internal/osmgmt"
)

func writeLines(t *testing.T, path string, n int) {
	t.Helper()
	var b strings.Builder
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&b, "line %d\n", i)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o640); err != nil {
		t.Fatalf("could not write fixture: %v", err)
	}
}

func TestTailCapLogTrimsToTheNewestLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "laps.log")
	writeLines(t, path, localLogMaxLines+500)

	tailCapLog(path)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("could not read the capped log: %v", err)
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) != localLogMaxLines {
		t.Errorf("capped log has %d lines, want %d", len(lines), localLogMaxLines)
	}
	if !strings.Contains(string(data), fmt.Sprintf("line %d", localLogMaxLines+500)) {
		t.Error("the newest line was trimmed away")
	}
	if strings.Contains(string(data), "line 1\n") {
		t.Error("the oldest line survived the cap")
	}
}

func TestTailCapLogLeavesShortLogAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "laps.log")
	writeLines(t, path, 10)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("could not read fixture: %v", err)
	}

	tailCapLog(path)

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("could not read the log: %v", err)
	}
	if string(before) != string(after) {
		t.Error("a log below the cap was rewritten")
	}
}

func TestTailCapLogHandlesMissingFile(t *testing.T) {
	tailCapLog(filepath.Join(t.TempDir(), "does-not-exist.log"))
}

func TestTailCapLogLeavesNoTempFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "laps.log")
	writeLines(t, path, localLogMaxLines+10)

	tailCapLog(path)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("could not list the log directory: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("left a temporary log copy behind: %s", e.Name())
		}
	}
}

func TestRunLockExitCode(t *testing.T) {
	if got := runLockExitCode(false, nil); got != 0 {
		t.Fatalf("runLockExitCode(false, nil) = %d, want 0", got)
	}
	if got := runLockExitCode(true, nil); got != exitCodeTempFail {
		t.Fatalf("runLockExitCode(true, nil) = %d, want %d", got, exitCodeTempFail)
	}
	if got := runLockExitCode(false, syscall.ELOOP); got != 1 {
		t.Fatalf("runLockExitCode(false, ELOOP) = %d, want 1", got)
	}
	if got := runLockExitCode(true, errors.New("lock error")); got != 1 {
		t.Fatalf("runLockExitCode(true, err) = %d, want 1", got)
	}
}

func TestPreflightExitCode(t *testing.T) {
	if got := preflightExitCode(nil); got != 0 {
		t.Fatalf("preflightExitCode(nil) = %d, want 0", got)
	}
	if got := preflightExitCode(fmt.Errorf("battery low: %w", osmgmt.ErrSkipRun)); got != exitCodeTempFail {
		t.Fatalf("preflightExitCode(ErrSkipRun) = %d, want %d", got, exitCodeTempFail)
	}
	if got := preflightExitCode(errors.New("not root")); got != 1 {
		t.Fatalf("preflightExitCode(other) = %d, want 1", got)
	}
}

func TestCapabilitiesIncludeSecretsStdin(t *testing.T) {
	joined := " " + strings.Join(capabilities, " ") + " "
	for _, word := range []string{"preflight", "secrets-stdin"} {
		if !strings.Contains(joined, " "+word+" ") {
			t.Errorf("capabilities lost %q: %q", word, joined)
		}
	}
}

func TestTailCapLogRefusesASymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need a privilege on Windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	writeLines(t, target, localLogMaxLines+10)
	before, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "laps.log")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	tailCapLog(link)

	after, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("the target of the link is gone: %v", err)
	}
	if string(before) != string(after) {
		t.Error("the cap wrote through the symlink")
	}
	info, err := os.Lstat(link)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the symlink was replaced by a file (err=%v)", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Errorf("the log directory holds %d entries, want the link and its target", len(entries))
	}
}

func TestTailCapLogKeepsTheMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no Unix mode bits")
	}
	path := filepath.Join(t.TempDir(), "laps.log")
	writeLines(t, path, localLogMaxLines+10)

	tailCapLog(path)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("capped log mode = %o, want 600", mode)
	}
}

func TestEffectiveRunBudgetTakesTheStartupDelayOff(t *testing.T) {
	for _, tc := range []struct {
		env  string
		want time.Duration
	}{
		{"", runBudget},
		{"garbage", runBudget},
		{"-5", runBudget},
		{"0", runBudget},
		{"600", runBudget - 10*time.Minute},
		{"900", runBudget - 15*time.Minute},
		{"3000", minRunBudget},
	} {
		if got := effectiveRunBudget(tc.env); got != tc.want {
			t.Errorf("effectiveRunBudget(%q) = %s, want %s", tc.env, got, tc.want)
		}
	}
}

func mainFunction(t *testing.T) string {
	t.Helper()
	src := readRepoFile(t, "cmd/main.go")
	start := strings.Index(src, "\nfunc main() {")
	if start < 0 {
		t.Fatal("main.go has no func main")
	}
	body := src[start:]
	end := strings.Index(body, "\n}\n")
	if end < 0 {
		t.Fatal("func main has no closing brace in column one")
	}
	return body[:end+3]
}

func TestMainTakesTheRunLockBeforeTheLog(t *testing.T) {
	m := mainFunction(t)
	lock := strings.Index(m, "acquireRunLock(runLockPath)")
	held := strings.Index(m, "runLockExitCode(held, err)")
	logSetup := strings.Index(m, "setupLocalLog()")
	if lock < 0 || held < 0 || logSetup < 0 {
		t.Fatalf("main lost a call: lock at %d, held check at %d, log setup at %d", lock, held, logSetup)
	}
	if lock > logSetup || held > logSetup {
		t.Errorf("main sets up the log (at %d) before it takes the run lock (at %d) and checks it (at %d)", logSetup, lock, held)
	}
}

func TestTriggerScriptStaysThin(t *testing.T) {
	script := readRepoFile(t, filepath.Join("scripts", "mdm", "macos", "laps_token.sh"))

	// "sleep" stays out of this list because the startup delay is a scheduling step, not a repair.
	for _, forbidden := range []string{"dscl", "pwpolicy", "security ", "dseditgroup", "pmset", "curl", "sysadminctl", "tail -n", "chmod"} {
		for _, line := range strings.Split(script, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue // a comment may name a moved tool
			}
			if strings.Contains(line, forbidden) {
				t.Errorf("laps_token.sh runs %q again — that logic belongs in the Go preflight: %s", forbidden, strings.TrimSpace(line))
			}
		}
	}
	for _, required := range []string{
		`__VAULT_SERVICE_TOKEN_OPTIONAL__`, `__LEGACY_ADMIN_PASSWORD_OPTIONAL__`, "exit 0", `"$LAPS_BINARY" --capabilities`, `*" preflight "*`, `*" secrets-stdin "*`,
		`"$LAPS_BINARY" --secrets-from-stdin`, `/usr/bin/env -i /usr/bin/caffeinate -i /bin/sleep "$DELAY"`,
		`printf '%s\n%s\n' "$LAPS_VAULT_TOKEN" "$LEGACY_ADMIN_PASS" |`,
		`cat <<'__GOLAPS_TOKEN_EOF__'`, `cat <<'__GOLAPS_LEGACY_EOF__'`,
	} {
		if !strings.Contains(script, required) {
			t.Errorf("laps_token.sh lost %q", required)
		}
	}
	for _, forbidden := range []string{`export LAPS_VAULT_TOKEN=`, `export LEGACY_ADMIN_PASS=`} {
		if strings.Contains(script, forbidden) {
			t.Errorf("laps_token.sh exports a secret at assignment: %q", forbidden)
		}
	}
	// Raise this cap only for a check that cannot live in Go.
	if n := len(strings.Split(strings.TrimSpace(script), "\n")); n > 120 {
		t.Errorf("laps_token.sh is %d lines — a trigger script this size is growing logic again", n)
	}
}

func trustedPathFunction(t *testing.T) (script, function string) {
	t.Helper()
	script = readRepoFile(t, filepath.Join("scripts", "mdm", "macos", "laps_token.sh"))
	start := strings.Index(script, "trusted_path() {")
	if start < 0 {
		t.Fatal("laps_token.sh has no trusted_path function")
	}
	end := strings.Index(script[start:], "\n}\n")
	if end < 0 {
		t.Fatal("the trusted_path function of laps_token.sh has no end")
	}
	return script, script[start : start+end+3]
}

func TestTriggerChecksTheBinaryBeforeItRunsIt(t *testing.T) {
	script, _ := trustedPathFunction(t)
	check := strings.Index(script, `if ! trusted_path "$LAPS_BINARY"; then`)
	firstStart := strings.Index(script, `"$LAPS_BINARY" --capabilities`)
	if check < 0 || firstStart < 0 || check > firstStart {
		t.Fatalf("laps_token.sh must check the binary with trusted_path before it starts it (check at %d, first start at %d)", check, firstStart)
	}
	refusal := script[check:firstStart]
	if !strings.Contains(refusal, "[UNTRUSTED BINARY]") || !strings.Contains(refusal, "exit 1") {
		t.Errorf("the refusal must log [UNTRUSTED BINARY] and exit 1: %s", refusal)
	}
}

func TestTrustedPathOfTheTrigger(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("the function uses the stat of macOS")
	}
	if os.Getuid() == 0 {
		t.Skip("root owns the test files, so the owner check cannot fail")
	}
	_, function := trustedPathFunction(t)
	dir := t.TempDir()
	own := filepath.Join(dir, "golaps")
	if err := os.WriteFile(own, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink("/usr/bin/true", link); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, path, want string
		code             int
	}{
		{"a system binary with a root-owned chain", "/usr/bin/true", "", 0},
		{"a file of another owner", own, "not by root", 1},
		{"a symbolic link", link, "is a symbolic link", 1},
		{"a directory that everyone can write", "/private/tmp", "writable by group or other", 1},
		{"a directory that only a group can write", "/Applications", "writable by group or other", 1},
		{"a root-owned entry below a directory that a group can write", "/Applications/Utilities", "/Applications is writable by group or other", 1},
		{"a root-owned directory with a trusted chain", "/usr/bin", "is not a regular file", 1},
		{"a path that does not exist", "/usr/bin/no_such_binary_of_laps", "cannot be checked", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			program := "log() { echo \"$1\"; }\n" + function + "\ntrusted_path \"$1\"\n"
			out, err := exec.Command("/bin/bash", "-c", program, "bash", tc.path).CombinedOutput()
			code := 0
			if exit, ok := err.(*exec.ExitError); ok {
				code = exit.ExitCode()
			} else if err != nil {
				t.Fatalf("bash did not run: %v", err)
			}
			if code != tc.code {
				t.Errorf("exit code = %d, want %d (output: %s)", code, tc.code, out)
			}
			if tc.want == "" && len(out) != 0 {
				t.Errorf("a trusted path must give no output, got: %s", out)
			}
			if !strings.Contains(string(out), tc.want) {
				t.Errorf("output = %q, want it to name %q", out, tc.want)
			}
		})
	}
}

func readRepoFile(t *testing.T, relPath string) string {
	t.Helper()
	path := filepath.Join("..", relPath)
	if strings.HasPrefix(relPath, "cmd/") || strings.HasPrefix(relPath, `cmd\`) {
		path = strings.TrimPrefix(strings.TrimPrefix(relPath, "cmd/"), `cmd\`)
	}
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read %s: %v", relPath, err)
	}
	return strings.ReplaceAll(string(src), "\r\n", "\n")
}

func TestInstallPathsAgree(t *testing.T) {
	build := readRepoFile(t, filepath.Join("scripts", "build", "build.sh"))
	trigger := readRepoFile(t, filepath.Join("scripts", "mdm", "macos", "laps_token.sh"))
	audit := readRepoFile(t, filepath.Join("scripts", "mdm", "macos", "audit_laps_customapp.sh"))
	for file, lines := range map[string][]string{
		"build.sh": {
			`MAC_BINARY_PATH="/usr/local/bin/golaps"`,
			`MAC_HELPER_PATH="/usr/local/bin/mac_helper"`,
			`MAC_AUTH_WINDOW_PATH="/usr/local/bin/golaps_auth"`,
			`MAC_BACKDROP_PATH="/usr/local/golaps/backdrop.jpg"`,
		},
		"laps_token.sh": {`LAPS_BINARY="/usr/local/bin/golaps"`},
		"audit_laps_customapp.sh": {
			`BINARY_PATH="/usr/local/bin/golaps"`,
			`HELPER_PATH="/usr/local/bin/mac_helper"`,
			`AUTH_WINDOW_PATH="/usr/local/bin/golaps_auth"`,
		},
	} {
		text := map[string]string{"build.sh": build, "laps_token.sh": trigger, "audit_laps_customapp.sh": audit}[file]
		for _, line := range lines {
			if !strings.Contains(text, "\n"+line+"\n") {
				t.Errorf("%s has no line %s", file, line)
			}
		}
	}
}

func TestAuditChecksHelperAndWindow(t *testing.T) {
	audit := readRepoFile(t, filepath.Join("scripts", "mdm", "macos", "audit_laps_customapp.sh"))
	build := readRepoFile(t, filepath.Join("scripts", "build", "build.sh"))
	version := strings.Index(audit, `"$INSTALLED_VERSION" != "$EXPECTED_VERSION"`)
	if version < 0 {
		t.Fatal("the audit has no EXPECTED_VERSION comparison")
	}
	for _, check := range []string{`[ ! -f "$HELPER_PATH" ]`, `[ ! -f "$AUTH_WINDOW_PATH" ]`} {
		at := strings.Index(audit, check)
		if at < 0 {
			t.Errorf("the audit has no check %s", check)
		} else if at < version {
			t.Errorf("the check %s comes before the version check", check)
		}
	}
	pack := strings.Index(build, "pkgbuild --root")
	if pack < 0 {
		t.Fatal("build.sh has no pkgbuild line")
	}
	for _, check := range []string{`[ -f "$PAYLOAD_ROOT$MAC_HELPER_PATH" ]`, `[ -f "$PAYLOAD_ROOT$MAC_AUTH_WINDOW_PATH" ]`} {
		at := strings.Index(build, "\n"+check)
		if at < 0 {
			t.Errorf("build.sh has no payload check %s", check)
		} else if at > pack {
			t.Errorf("the payload check %s comes after pkgbuild", check)
		}
	}
}

func TestBuildTestsBeforeItBuilds(t *testing.T) {
	build := readRepoFile(t, filepath.Join("scripts", "build", "build.sh"))
	clean := strings.Index(build, `rm -rf "$RELEASE_DIR"`)
	if clean < 0 {
		t.Fatal(`build.sh has no rm -rf "$RELEASE_DIR" line`)
	}
	for _, step := range []string{"go vet ./...", "go test ./..."} {
		at := strings.Index(build, "\n"+step+" ||")
		if at < 0 {
			t.Errorf("build.sh has no line %s", step)
		} else if at > clean {
			t.Errorf("%s comes after the line that removes the release directory", step)
		}
	}
}
