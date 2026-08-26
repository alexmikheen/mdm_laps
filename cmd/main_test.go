package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	// The newest entries are the ones worth keeping — this file exists precisely because the MDM console throws away everything but the latest run.
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
	// First run on a fresh device: nothing to cap, and certainly nothing to crash over.
	tailCapLog(filepath.Join(t.TempDir(), "does-not-exist.log"))
}

// A temporary copy of the log is a second file full of local account names; it must not be left behind under a name nobody rotates.
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
