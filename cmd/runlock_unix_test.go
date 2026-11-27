// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

//go:build !windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
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
	if !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("acquire on symlink returned %v, want ELOOP", err)
	}
}

func TestLocalLogOpenRefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "laps.log")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	f, err := openLogNoFollow(link)
	if err == nil {
		f.WriteString("leaked\n")
		f.Close()
		t.Fatal("the open followed a symlink")
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Errorf("the target of the link received %q", data)
	}
}

func TestLocalLogReadRefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "laps.log")
	if err := os.WriteFile(target, []byte("not for the cap\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if data, err := readLogNoFollow(link); err == nil {
		t.Fatalf("the read followed a symlink and returned %q", data)
	}
	if data, err := readLogNoFollow(target); err != nil || string(data) != "not for the cap\n" {
		t.Fatalf("the read of a plain file gave %q, %v", data, err)
	}
}

func TestLocalLogOpenCreatesAndAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "laps.log")
	for i := 0; i < 2; i++ {
		f, err := openLogNoFollow(path)
		if err != nil {
			t.Fatalf("open %d: %v", i+1, err)
		}
		f.WriteString("run\n")
		f.Close()
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("log mode = %o, want 600", mode)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "run\nrun\n" {
		t.Errorf("log holds %q, want two appended lines", data)
	}
}
