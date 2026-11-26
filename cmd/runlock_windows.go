// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

//go:build windows

package main

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// Use a Global kernel mutex so unprivileged users cannot pre-create or hold a shared lock.
const runLockPath = `Global\GoLAPS_RunLock`

var runLock windows.Handle

func acquireRunLock(name string) (h windows.Handle, held bool, err error) {
	ptr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, false, err
	}
	h, err = windows.CreateMutex(nil, false, ptr)
	if err != nil {
		if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			if h != 0 {
				_ = windows.CloseHandle(h)
			}
			return 0, true, nil
		}
		return 0, false, err
	}
	return h, false, nil
}

func disableCoreDumps() error {
	return nil
}

func openLogNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
}

func readLogNoFollow(path string) ([]byte, error) {
	return os.ReadFile(path)
}
