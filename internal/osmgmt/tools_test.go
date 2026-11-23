// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

//go:build darwin

package osmgmt

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestToolPathsAreAbsoluteAndInstalled(t *testing.T) {
	installed := []string{
		toolSysadminctl, toolDscl, toolDseditgroup, toolPwpolicy, toolFdesetup, toolProfiles,
		toolDiskutil, toolID, toolIoreg, toolOdutil, toolPmset, toolDsmemberutil, toolLaunchctl,
		toolSudo, toolSh, toolSecurity, toolLog, toolScutil, toolAwk, toolOpen,
	}
	for _, path := range installed {
		if !filepath.IsAbs(path) {
			t.Errorf("%q is not an absolute path", path)
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("%s is not installed on this Mac: %v", path, err)
			continue
		}
		if info.IsDir() || info.Mode()&0o111 == 0 {
			t.Errorf("%s is not an executable file (mode %v)", path, info.Mode())
		}
	}
	for _, path := range []string{helperPath, authWindowPath} {
		if !filepath.IsAbs(path) || filepath.Dir(path) != "/usr/local/bin" {
			t.Errorf("%q must be an absolute path below /usr/local/bin", path)
		}
	}
}

func TestExecRunnerPassesOnlyTheFixedEnvironment(t *testing.T) {
	t.Setenv("LAPS_LEAK_PROBE", "must-not-reach-the-child")
	t.Setenv("DYLD_INSERT_LIBRARIES", "/tmp/evil.dylib")

	out, err := execRunner{}.Run(context.Background(), "", "/usr/bin/env")
	if err != nil {
		t.Fatalf("env failed: %v | %s", err, out)
	}
	if string(out) != "PATH=/usr/bin:/bin:/usr/sbin:/sbin\n" {
		t.Fatalf("the child saw this environment:\n%s", out)
	}

	out, err = commandContext(context.Background(), "/usr/bin/env").Output()
	if err != nil {
		t.Fatalf("env failed: %v | %s", err, out)
	}
	if string(out) != "PATH=/usr/bin:/bin:/usr/sbin:/sbin\n" {
		t.Fatalf("the child of commandContext saw this environment:\n%s", out)
	}
}

type fakeFileInfo struct {
	name string
	mode os.FileMode
	uid  uint32
}

func (f fakeFileInfo) Name() string       { return f.name }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() os.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeFileInfo) Sys() any           { return &syscall.Stat_t{Uid: f.uid} }

func fakeTree(entries map[string]fakeFileInfo) func(string) (os.FileInfo, error) {
	return func(path string) (os.FileInfo, error) {
		info, ok := entries[path]
		if !ok {
			return nil, &os.PathError{Op: "lstat", Path: path, Err: os.ErrNotExist}
		}
		return info, nil
	}
}

func rootOwnedTree(path string) map[string]fakeFileInfo {
	entries := map[string]fakeFileInfo{path: {name: filepath.Base(path), mode: 0o755}}
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		entries[dir] = fakeFileInfo{name: filepath.Base(dir), mode: os.ModeDir | 0o755}
		if dir == "/" {
			return entries
		}
	}
}

func rootOwnedLstat(path string) (os.FileInfo, error) {
	entries := rootOwnedTree(helperPath)
	for dir, info := range rootOwnedTree(authWindowPath) {
		entries[dir] = info
	}
	return fakeTree(entries)(path)
}

func TestCheckTrustedPath(t *testing.T) {
	const path = "/usr/local/bin/mac_helper"
	for _, tt := range []struct {
		name   string
		change func(entries map[string]fakeFileInfo)
		want   string // a part of the error, empty for a pass
	}{
		{name: "root-owned chain passes"},
		{name: "group-writable directory fails", change: func(e map[string]fakeFileInfo) {
			e["/usr/local"] = fakeFileInfo{name: "local", mode: os.ModeDir | 0o775}
		}, want: "/usr/local is writable by group or other (mode 0775)"},
		{name: "world-writable bin directory fails", change: func(e map[string]fakeFileInfo) {
			e["/usr/local/bin"] = fakeFileInfo{name: "bin", mode: os.ModeDir | 0o777}
		}, want: "/usr/local/bin is writable by group or other"},
		{name: "symlink helper fails", change: func(e map[string]fakeFileInfo) {
			e[path] = fakeFileInfo{name: "mac_helper", mode: os.ModeSymlink | 0o755}
		}, want: path + " is a symbolic link"},
		{name: "symlink directory fails", change: func(e map[string]fakeFileInfo) {
			e["/usr/local"] = fakeFileInfo{name: "local", mode: os.ModeSymlink | 0o755}
		}, want: "/usr/local is a symbolic link"},
		{name: "non-root helper fails", change: func(e map[string]fakeFileInfo) {
			e[path] = fakeFileInfo{name: "mac_helper", mode: 0o755, uid: 501}
		}, want: path + " is owned by uid 501, not by root"},
		{name: "non-root directory fails", change: func(e map[string]fakeFileInfo) {
			e["/usr/local/bin"] = fakeFileInfo{name: "bin", mode: os.ModeDir | 0o755, uid: 501}
		}, want: "/usr/local/bin is owned by uid 501"},
		{name: "group-writable helper fails", change: func(e map[string]fakeFileInfo) {
			e[path] = fakeFileInfo{name: "mac_helper", mode: 0o775}
		}, want: path + " is writable by group or other (mode 0775)"},
		{name: "missing helper fails", change: func(e map[string]fakeFileInfo) {
			delete(e, path)
		}, want: path + " cannot be checked"},
		{name: "a directory in place of the helper fails", change: func(e map[string]fakeFileInfo) {
			e[path] = fakeFileInfo{name: "mac_helper", mode: os.ModeDir | 0o755}
		}, want: path + " is not a regular file"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			entries := rootOwnedTree(path)
			if tt.change != nil {
				tt.change(entries)
			}
			err := checkTrustedPath(path, fakeTree(entries))
			if tt.want == "" {
				if err != nil {
					t.Fatalf("a root-owned chain must pass, got: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got %v, want an error that contains %q", err, tt.want)
			}
		})
	}
}

func TestTrustedBinaryFailsWithoutAnLstat(t *testing.T) {
	m := &MacOSManager{}
	if err := m.trustedBinary(helperPath); !errors.Is(err, errNoFileCheck) {
		t.Fatalf("got %v, want errNoFileCheck", err)
	}
}

func TestRunSwiftHelperRefusesAnUntrustedHelper(t *testing.T) {
	f := &fakeRunner{}
	f.handle = func(c call) ([]byte, error) {
		t.Fatalf("no command may run, the helper failed its check: %s", c)
		return nil, nil
	}
	m := newTestManager(t, f)
	entries := rootOwnedTree(helperPath)
	entries[helperPath] = fakeFileInfo{name: "mac_helper", mode: 0o755, uid: 501}
	m.lstat = fakeTree(entries)

	var err error
	logged := captureLog(func() {
		_, err = m.runSwiftHelper(context.Background(), SwiftPayload{Action: "verify_password", TargetUser: "alice", TargetPass: "Secret-1"})
	})

	if err == nil || !strings.Contains(err.Error(), helperPath+" is owned by uid 501") {
		t.Fatalf("got %v, want the refusal with the path and the reason", err)
	}
	if !strings.Contains(logged, "[ERROR]") || !strings.Contains(logged, helperPath+" is owned by uid 501") {
		t.Fatalf("the log must carry an [ERROR] with the path and the reason:\n%s", logged)
	}
	if strings.Contains(logged, "Secret-1") || strings.Contains(err.Error(), "Secret-1") {
		t.Fatal("the password leaked into the log or the error")
	}
	if f.count("mac_helper") != 0 {
		t.Fatalf("the helper ran although it failed the check: %v", f.calls)
	}
}

func TestOpenAuthWindowRefusesAnUntrustedWindow(t *testing.T) {
	m := newTestManager(t, &fakeRunner{})
	entries := rootOwnedTree(authWindowPath)
	entries[authWindowPath] = fakeFileInfo{name: "golaps_auth", mode: os.ModeSymlink | 0o755}
	m.lstat = fakeTree(entries)

	win, err := m.openAuthWindow(context.Background(), "501", "alice", dialogRequest{Attempt: 1, MaxAttempts: 5})
	if win != nil || err == nil || !strings.Contains(err.Error(), authWindowPath+" is a symbolic link") {
		t.Fatalf("got (%v, %v), want a refusal that names the path and the reason", win, err)
	}
}
