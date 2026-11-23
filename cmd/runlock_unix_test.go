// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunLockRefusesASecondHolder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "golaps.lock")

	first, held, err := acquireRunLock(path)
	if err != nil {
		t.Fatalf("first acquire failed: %v", err)
	}
	if held {
		t.Fatal("first acquire reports the lock as held")
	}
	defer first.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("lock file missing: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("lock file mode = %o, want 600", mode)
	}

	second, held, err := acquireRunLock(path)
	if err != nil {
		t.Fatalf("second acquire failed instead of reporting the lock as held: %v", err)
	}
	if !held {
		second.Close()
		t.Fatal("second acquire did not report the lock as held")
	}
	if second != nil {
		t.Error("a refused acquire must not keep the file open")
	}

	first.Close()
	third, held, err := acquireRunLock(path)
	if err != nil || held {
		t.Fatalf("acquire after release: held=%v err=%v", held, err)
	}
	third.Close()
}

func TestRunLockRefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "golaps.lock")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	f, held, err := acquireRunLock(link)
	if err == nil {
		f.Close()
		t.Fatalf("acquire followed a symlink (held=%v)", held)
	}
}
