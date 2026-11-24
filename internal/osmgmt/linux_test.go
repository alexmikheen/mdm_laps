// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

package osmgmt

import (
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"
)

type linuxFakeFileInfo struct {
	name string
	mode fs.FileMode
}

func (f linuxFakeFileInfo) Name() string       { return f.name }
func (f linuxFakeFileInfo) Size() int64        { return 0 }
func (f linuxFakeFileInfo) Mode() fs.FileMode  { return f.mode }
func (f linuxFakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f linuxFakeFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f linuxFakeFileInfo) Sys() any           { return nil }

func TestLinuxChildEnvIsClean(t *testing.T) {
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "must-not-leak")
	t.Setenv("LEGACY_ADMIN_PASS", "must-not-leak-either")

	env := linuxChildEnv()
	if len(env) != 1 || env[0] != "PATH=/usr/sbin:/usr/bin:/sbin:/bin" {
		t.Fatalf("linuxChildEnv() = %v, want [PATH=/usr/sbin:/usr/bin:/sbin:/bin]", env)
	}
}

func TestValidateLinuxSerial(t *testing.T) {
	badValues := []string{
		"",
		"   \n\t ",
		"Unknown",
		"unknown",
		"To be filled by O.E.M.",
		"TO BE FILLED BY O.E.M.",
		"Default string",
		"0",
		"00000000",
		"00000000-0000-0000-0000-000000000000",
		"FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
		"ffffffffffffffff",
		"System Serial Number",
		"Chassis Serial Number",
		"Board Serial Number",
		"Base Board Serial Number",
		"Not Specified",
		"Not Applicable",
		"Not Available",
		"None",
		"N/A",
		"Invalid",
		"Empty",
		"O.E.M.",
		"uninitialized",
		"UNINITIALIZED",
		"bad\x00serial",
		"bad\x1bserial",
		"line1\nline2",
	}
	for _, bad := range badValues {
		if got, err := validateLinuxSerial(bad); err == nil {
			t.Fatalf("validateLinuxSerial(%q) = %q, want error", bad, got)
		}
	}

	goodValues := []string{
		"PF2ABCDE",
		" 5CD1234XYZ\n",
		"VMware-56 4d 12 ab",
		"7967FCD2-0CE4-4C0E-AE6C-F66536181D11",
		"4c8f2b1e9a7d4c3b8e1f0a2d5c6b7e8f",
	}
	for _, good := range goodValues {
		got, err := validateLinuxSerial(good)
		if err != nil {
			t.Fatalf("validateLinuxSerial(%q) returned error: %v", good, err)
		}
		if got != strings.TrimSpace(good) {
			t.Fatalf("validateLinuxSerial(%q) = %q, want %q", good, got, strings.TrimSpace(good))
		}
	}
}

func TestSelectLinuxSerialFallbackOrder(t *testing.T) {
	files := map[string]string{
		"/sys/class/dmi/id/product_serial": "To be filled by O.E.M.\n",
		"/sys/class/dmi/id/board_serial":   "00000000\n",
		"/sys/class/dmi/id/product_uuid":   "7967FCD2-0CE4-4C0E-AE6C-F66536181D11\n",
		"/etc/machine-id":                  "4c8f2b1e9a7d4c3b8e1f0a2d5c6b7e8f\n",
	}
	readFile := func(path string) ([]byte, error) {
		val, ok := files[path]
		if !ok {
			return nil, os.ErrNotExist
		}
		return []byte(val), nil
	}

	got, err := selectLinuxSerial(readFile, linuxSerialPaths)
	if err != nil {
		t.Fatalf("selectLinuxSerial failed: %v", err)
	}
	if got != "7967FCD2-0CE4-4C0E-AE6C-F66536181D11" {
		t.Fatalf("selectLinuxSerial = %q, want product_uuid", got)
	}

	delete(files, "/sys/class/dmi/id/product_uuid")
	got, err = selectLinuxSerial(readFile, linuxSerialPaths)
	if err != nil {
		t.Fatalf("selectLinuxSerial machine-id fallback failed: %v", err)
	}
	if got != "4c8f2b1e9a7d4c3b8e1f0a2d5c6b7e8f" {
		t.Fatalf("selectLinuxSerial = %q, want machine-id", got)
	}

	delete(files, "/etc/machine-id")
	if _, err := selectLinuxSerial(readFile, linuxSerialPaths); err == nil {
		t.Fatal("selectLinuxSerial succeeded with no valid sources")
	}
}

func TestValidateChpasswdInput(t *testing.T) {
	cases := []struct {
		name    string
		user    string
		pass    string
		wantErr bool
	}{
		{"valid", "lapsadmin", "Sup3r:S3cret!Pass", false},
		{"valid with punctuation", "_laps.admin-1", "Sup3rS3cret!", false},
		{"empty user", "", "Sup3rS3cret!", true},
		{"root user", "root", "Sup3rS3cret!", true},
		{"leading dash short", "-o", "Sup3rS3cret!", true},
		{"leading dash long", "--help", "Sup3rS3cret!", true},
		{"uid zero", "0", "Sup3rS3cret!", true},
		{"numeric uid", "1000", "Sup3rS3cret!", true},
		{"space in user", "a b", "Sup3rS3cret!", true},
		{"colon in user", "laps:admin", "Sup3rS3cret!", true},
		{"newline in user", "laps\nroot", "Sup3rS3cret!", true},
		{"cr in user", "laps\rroot", "Sup3rS3cret!", true},
		{"nul in user", "laps\x00admin", "Sup3rS3cret!", true},
		{"empty pass", "lapsadmin", "", true},
		{"newline in pass", "lapsadmin", "pass1\nroot:pwned", true},
		{"cr in pass", "lapsadmin", "pass1\rroot:pwned", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateChpasswdInput(tc.user, tc.pass)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateChpasswdInput(%q, %q) err = %v, wantErr %v", tc.user, tc.pass, err, tc.wantErr)
			}
		})
	}
}

func TestScrubSecret(t *testing.T) {
	got := scrubSecret("chpasswd: secret123 rejected (secret123)", "secret123")
	if strings.Contains(got, "secret123") {
		t.Fatalf("scrubSecret leaked secret: %q", got)
	}
	if got != "chpasswd: [REDACTED] rejected ([REDACTED])" {
		t.Fatalf("scrubSecret = %q", got)
	}
	if unchanged := scrubSecret("plain output", ""); unchanged != "plain output" {
		t.Fatalf("scrubSecret with empty secret = %q", unchanged)
	}
}

func TestResolveLinuxTool(t *testing.T) {
	entries := map[string]linuxFakeFileInfo{
		"/usr/sbin/chpasswd": {name: "chpasswd", mode: 0o755},
		"/sbin/usermod":      {name: "usermod", mode: 0o755},
		"/usr/bin/id":        {name: "id", mode: 0o755},
		"/usr/sbin/badfile":  {name: "badfile", mode: 0o644},
		"/usr/sbin/baddir":   {name: "baddir", mode: fs.ModeDir | 0o755},
	}
	stat := func(path string) (os.FileInfo, error) {
		info, ok := entries[path]
		if !ok {
			return nil, os.ErrNotExist
		}
		return info, nil
	}

	got, err := resolveLinuxTool("chpasswd", stat)
	if err != nil || got != "/usr/sbin/chpasswd" {
		t.Fatalf("resolveLinuxTool(chpasswd) = (%q, %v)", got, err)
	}
	got, err = resolveLinuxTool("usermod", stat)
	if err != nil || got != "/sbin/usermod" {
		t.Fatalf("resolveLinuxTool(usermod) = (%q, %v)", got, err)
	}
	got, err = resolveLinuxTool("id", stat)
	if err != nil || got != "/usr/bin/id" {
		t.Fatalf("resolveLinuxTool(id) = (%q, %v)", got, err)
	}
	for _, bad := range []string{"", "../chpasswd", "missing", "badfile", "baddir"} {
		if p, err := resolveLinuxTool(bad, stat); err == nil {
			t.Fatalf("resolveLinuxTool(%q) = %q, want error", bad, p)
		}
	}
}

func TestSelectLinuxShell(t *testing.T) {
	withBash := func(path string) (os.FileInfo, error) {
		if path == "/bin/bash" {
			return linuxFakeFileInfo{name: "bash", mode: 0o755}, nil
		}
		return nil, os.ErrNotExist
	}
	if got := selectLinuxShell(withBash); got != "/bin/bash" {
		t.Fatalf("selectLinuxShell(withBash) = %q, want /bin/bash", got)
	}

	withoutBash := func(path string) (os.FileInfo, error) {
		return nil, os.ErrNotExist
	}
	if got := selectLinuxShell(withoutBash); got != "/bin/sh" {
		t.Fatalf("selectLinuxShell(withoutBash) = %q, want /bin/sh", got)
	}
}

func TestDetectLinuxAdminGroup(t *testing.T) {
	debian := func(group string) (string, error) {
		if group == "sudo" {
			return "sudo:x:27:alice", nil
		}
		return "", errors.New("exit status 2")
	}
	got, err := detectLinuxAdminGroup(debian)
	if err != nil || got != "sudo" {
		t.Fatalf("detectLinuxAdminGroup(debian) = (%q, %v), want sudo", got, err)
	}

	rhel := func(group string) (string, error) {
		if group == "wheel" {
			return "wheel:x:10:bob", nil
		}
		return "", errors.New("exit status 2")
	}
	got, err = detectLinuxAdminGroup(rhel)
	if err != nil || got != "wheel" {
		t.Fatalf("detectLinuxAdminGroup(rhel) = (%q, %v), want wheel", got, err)
	}

	none := func(group string) (string, error) {
		return "", errors.New("exit status 2")
	}
	if _, err := detectLinuxAdminGroup(none); err == nil {
		t.Fatal("detectLinuxAdminGroup(none) succeeded, want error")
	}

	malformed := func(group string) (string, error) {
		return "not-a-group-line", nil
	}
	if _, err := detectLinuxAdminGroup(malformed); err == nil {
		t.Fatal("detectLinuxAdminGroup(malformed) succeeded, want error")
	}
}
