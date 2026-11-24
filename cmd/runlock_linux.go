// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

//go:build linux

package main

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// disableCoreDumps sets RLIMIT_CORE to zero and clears the Linux dumpable flag.
func disableCoreDumps() error {
	rlimitErr := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0})
	prctlErr := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
	if rlimitErr != nil && prctlErr != nil {
		return fmt.Errorf("setrlimit RLIMIT_CORE: %w; prctl PR_SET_DUMPABLE: %v", rlimitErr, prctlErr)
	}
	if prctlErr != nil {
		return fmt.Errorf("prctl PR_SET_DUMPABLE: %w", prctlErr)
	}
	return rlimitErr
}
