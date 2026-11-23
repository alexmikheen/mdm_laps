// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

//go:build darwin

package osmgmt

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// Every Apple tool is invoked by its absolute path with a fixed system PATH so an inherited PATH or DYLD variable never reaches a root child process.
const (
	toolSysadminctl  = "/usr/sbin/sysadminctl"
	toolDscl         = "/usr/bin/dscl"
	toolDseditgroup  = "/usr/sbin/dseditgroup"
	toolPwpolicy     = "/usr/bin/pwpolicy"
	toolFdesetup     = "/usr/bin/fdesetup"
	toolProfiles     = "/usr/bin/profiles"
	toolDiskutil     = "/usr/sbin/diskutil"
	toolID           = "/usr/bin/id"
	toolIoreg        = "/usr/sbin/ioreg"
	toolOdutil       = "/usr/bin/odutil"
	toolPmset        = "/usr/bin/pmset"
	toolDsmemberutil = "/usr/bin/dsmemberutil"
	toolLaunchctl    = "/bin/launchctl"
	toolSudo         = "/usr/bin/sudo"
	toolSh           = "/bin/sh"
	toolSecurity     = "/usr/bin/security"
	toolLog          = "/usr/bin/log"
	toolScutil       = "/usr/sbin/scutil"
	toolAwk          = "/usr/bin/awk"
	toolOpen         = "/usr/bin/open"

	// helperPath is the Swift helper that receives passwords over stdin.
	helperPath = "/usr/local/bin/mac_helper"
)

const childPath = "PATH=/usr/bin:/bin:/usr/sbin:/sbin"

func childEnv() []string {
	return []string{childPath}
}

func commandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = childEnv()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 5 * time.Second
	cmd.Cancel = func() error {
		if cmd.Process == nil || cmd.Process.Pid <= 0 {
			return os.ErrProcessDone
		}
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		} else {
			return err
		}
	}
	return cmd
}

var errNoFileCheck = errors.New("no file check is configured")

// trustedBinary verifies that path and every parent directory up to "/" are root-owned, not symlinks, and not writable by group or other.
func (m *MacOSManager) trustedBinary(path string) error {
	if m.lstat == nil {
		return fmt.Errorf("%s: %w", path, errNoFileCheck)
	}
	return checkTrustedPath(path, m.lstat)
}

func checkTrustedPath(path string, lstat func(string) (os.FileInfo, error)) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%s is not an absolute path", path)
	}
	if err := checkTrustedEntry(path, lstat, false); err != nil {
		return err
	}
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		if err := checkTrustedEntry(dir, lstat, true); err != nil {
			return err
		}
		if dir == "/" {
			return nil
		}
	}
}

func checkTrustedEntry(path string, lstat func(string) (os.FileInfo, error), wantDir bool) error {
	info, err := lstat(path)
	if err != nil {
		return fmt.Errorf("%s cannot be checked: %w", path, err)
	}
	mode := info.Mode()
	if mode&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symbolic link", path)
	}
	if wantDir && !mode.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}
	if !wantDir && !mode.IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	uid, ok := fileOwner(info)
	if !ok {
		return fmt.Errorf("%s has no readable owner", path)
	}
	if uid != 0 {
		return fmt.Errorf("%s is owned by uid %d, not by root", path, uid)
	}
	if perm := mode.Perm(); perm&0o022 != 0 {
		return fmt.Errorf("%s is writable by group or other (mode %04o)", path, perm)
	}
	return nil
}

func fileOwner(info os.FileInfo) (uid uint32, ok bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, false
	}
	return st.Uid, true
}
