// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

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
