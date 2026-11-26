// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

//go:build !windows

package main

import (
	"errors"
	"io"
	"os"
	"syscall"
)

var runLockPath = "/var/run/golaps.lock"
var runLock *os.File

func acquireRunLock(path string) (f *os.File, held bool, err error) {
	f, err = os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, false, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, true, nil
		}
		return nil, false, err
	}
	return f, false, nil
}

func openLogNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND|syscall.O_NOFOLLOW, 0o600)
}

// Open with O_NOFOLLOW instead of an lstat because a separate read leaves a window between check and open.
func readLogNoFollow(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}
