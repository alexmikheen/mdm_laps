// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

//go:build darwin

package main

import "syscall"

// disableCoreDumps sets RLIMIT_CORE to zero on macOS.
func disableCoreDumps() error {
	return syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0})
}
