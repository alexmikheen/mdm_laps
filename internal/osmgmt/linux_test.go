// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

package osmgmt

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"strings"
	"testing"
	"time"
)

type linuxFakeFileInfo struct {
	name string
	mode fs.FileMode
	uid  uint32
}

func (f linuxFakeFileInfo) Name() string       { return f.name }
func (f linuxFakeFileInfo) Size() int64        { return 0 }
func (f linuxFakeFileInfo) Mode() fs.FileMode  { return f.mode }
func (f linuxFakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f linuxFakeFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f linuxFakeFileInfo) Sys() any           { return nil }
func (f linuxFakeFileInfo) OwnerUID() uint32   { return f.uid }

func linuxBaseRootTree() map[string]linuxFakeFileInfo {
	return map[string]linuxFakeFileInfo{
		"/":         {name: "/", mode: fs.ModeDir | 0o755, uid: 0},
		"/usr":      {name: "usr", mode: fs.ModeDir | 0o755, uid: 0},
		"/usr/sbin": {name: "sbin", mode: fs.ModeDir | 0o755, uid: 0},
		"/usr/bin":  {name: "bin", mode: fs.ModeDir | 0o755, uid: 0},
		"/sbin":     {name: "sbin", mode: fs.ModeDir | 0o755, uid: 0},
		"/bin":      {name: "bin", mode: fs.ModeDir | 0o755, uid: 0},
	}
}

func makeLinuxToolFS(entries map[string]linuxFakeFileInfo, symlinks map[string]string) linuxToolFS {
	stat := func(p string) (os.FileInfo, error) {
		if target, ok := symlinks[p]; ok {
			p = target
		}
		info, ok := entries[p]
		if !ok {
			return nil, os.ErrNotExist
		}
		return info, nil
	}
	lstat := func(p string) (os.FileInfo, error) {
		if _, ok := symlinks[p]; ok {
			return linuxFakeFileInfo{name: path.Base(p), mode: fs.ModeSymlink | 0o777, uid: 0}, nil
		}
		info, ok := entries[p]
		if !ok {
			return nil, os.ErrNotExist
		}
		return info, nil
	}
	evalSymlinks := func(p string) (string, error) {
		if target, ok := symlinks[p]; ok {
			return target, nil
		}
		if _, ok := entries[p]; !ok {
			return "", os.ErrNotExist
		}
		return p, nil
	}
	return linuxToolFS{
		stat:         stat,
		lstat:        lstat,
		evalSymlinks: evalSymlinks,
	}
}

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
		"Default",
		"0",
		"00000000",
		"00000000-0000-0000-0000-000000000000",
		"FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
		"ffffffffffffffff",
		"XXXXXXXX",
		"1111-1111-1111",
		"--------",
		"123456789",
		"0123456789",
		"1234567890",
		"987654321",
		"abcdefgh",
		"System Serial Number",
		"System Product Name",
		"Chassis Serial Number",
		"Chassis Asset Tag",
		"Board Serial Number",
		"Base Board Serial Number",
		"Not Specified",
		"Not Settable",
		"Not Applicable",
		"Not Available",
		"Asset-1234567890",
		"asset-tag",
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
		"../other",
		"a/b",
		`a\b`,
		"abc..def",
		"abc?foo=1",
		"abc#frag",
		"abc%20def",
		".",
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
	readFile := func(p string) ([]byte, error) {
		val, ok := files[p]
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

func TestLookupLocalPasswdAndAccountGuard(t *testing.T) {
	passwd := strings.Join([]string{
		"root:x:0:0:root:/root:/bin/bash",
		"toor:x:0:0:GoLAPS managed:/root:/bin/bash",
		"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
		"syslaps:x:999:999:GoLAPS managed:/home/syslaps:/bin/bash",
		"alice:x:1001:1001:Alice Smith:/home/alice:/bin/bash",
		"lapsadmin:x:1002:1002:GoLAPS managed:/home/lapsadmin:/bin/bash",
		"legacy:x:1003:1003:GoLAPS managed local administrator:/home/legacy:/bin/bash",
	}, "\n")

	if _, ok := lookupLocalPasswd(passwd, "missing"); ok {
		t.Fatal("lookupLocalPasswd found nonexistent user")
	}

	uidMin := parseLoginDefsUIDMin("# comment\nUID_MIN\t1000\nUID_MAX 60000\n")
	if uidMin != 1000 {
		t.Fatalf("parseLoginDefsUIDMin = %d, want 1000", uidMin)
	}
	if custom := parseLoginDefsUIDMin("UID_MIN 500\n"); custom != 500 {
		t.Fatalf("parseLoginDefsUIDMin(500) = %d, want 500", custom)
	}
	if def := parseLoginDefsUIDMin(""); def != 1000 {
		t.Fatalf("parseLoginDefsUIDMin(empty) = %d, want 1000", def)
	}

	for _, rejectUser := range []string{"root", "toor", "www-data", "syslaps", "alice"} {
		entry, ok := lookupLocalPasswd(passwd, rejectUser)
		if !ok {
			t.Fatalf("expected %s in passwd fixture", rejectUser)
		}
		if err := validateManagedLocalAccount(entry, uidMin); err == nil {
			t.Fatalf("validateManagedLocalAccount(%s) succeeded, want error", rejectUser)
		}
	}
	for _, allowUser := range []string{"lapsadmin", "legacy"} {
		entry, ok := lookupLocalPasswd(passwd, allowUser)
		if !ok {
			t.Fatalf("expected %s in passwd fixture", allowUser)
		}
		if err := validateManagedLocalAccount(entry, uidMin); err != nil {
			t.Fatalf("validateManagedLocalAccount(%s) failed: %v", allowUser, err)
		}
	}
}

func TestResolveLinuxToolTrustAndUsrmerge(t *testing.T) {
	entries := linuxBaseRootTree()
	entries["/usr/sbin/chpasswd"] = linuxFakeFileInfo{name: "chpasswd", mode: 0o755, uid: 0}
	entries["/usr/sbin/usermod"] = linuxFakeFileInfo{name: "usermod", mode: 0o755, uid: 0}
	entries["/usr/bin/sudo"] = linuxFakeFileInfo{name: "sudo", mode: fs.ModeSetuid | 0o755, uid: 0}
	entries["/usr/sbin/badfile"] = linuxFakeFileInfo{name: "badfile", mode: 0o644, uid: 0}
	entries["/usr/sbin/baddir"] = linuxFakeFileInfo{name: "baddir", mode: fs.ModeDir | 0o755, uid: 0}
	entries["/usr/sbin/nonroot"] = linuxFakeFileInfo{name: "nonroot", mode: 0o755, uid: 1000}
	entries["/usr/sbin/writable"] = linuxFakeFileInfo{name: "writable", mode: 0o775, uid: 0}
	entries["/tmp"] = linuxFakeFileInfo{name: "tmp", mode: fs.ModeDir | 0o777, uid: 0}
	entries["/tmp/evil"] = linuxFakeFileInfo{name: "evil", mode: 0o755, uid: 0}

	symlinks := map[string]string{
		"/sbin/usrmerged": "/usr/sbin/usermod",
		"/usr/sbin/evil":  "/tmp/evil",
	}
	toolFS := makeLinuxToolFS(entries, symlinks)

	got, err := resolveLinuxTool("chpasswd", toolFS)
	if err != nil || got != "/usr/sbin/chpasswd" {
		t.Fatalf("resolveLinuxTool(chpasswd) = (%q, %v)", got, err)
	}
	got, err = resolveLinuxTool("usrmerged", toolFS)
	if err != nil || got != "/usr/sbin/usermod" {
		t.Fatalf("resolveLinuxTool(usrmerged) = (%q, %v), want /usr/sbin/usermod", got, err)
	}
	got, err = resolveLinuxTool("sudo", toolFS)
	if err != nil || got != "/usr/bin/sudo" {
		t.Fatalf("resolveLinuxTool(sudo) = (%q, %v)", got, err)
	}

	for _, bad := range []string{"", ".", "..", "../chpasswd", "missing", "badfile", "baddir", "nonroot", "writable", "evil"} {
		if p, err := resolveLinuxTool(bad, toolFS); err == nil {
			t.Fatalf("resolveLinuxTool(%q) = %q, want error", bad, p)
		}
	}

	// Untrusted parent directory must fail closed.
	entries["/usr/sbin"] = linuxFakeFileInfo{name: "sbin", mode: fs.ModeDir | 0o775, uid: 0}
	if p, err := resolveLinuxTool("chpasswd", toolFS); err == nil {
		t.Fatalf("resolveLinuxTool accepted binary in group-writable directory: %q", p)
	}
}

func TestSelectLinuxShell(t *testing.T) {
	withBash := func(p string) (os.FileInfo, error) {
		if p == "/bin/bash" {
			return linuxFakeFileInfo{name: "bash", mode: 0o755}, nil
		}
		return nil, os.ErrNotExist
	}
	if got := selectLinuxShell(withBash); got != "/bin/bash" {
		t.Fatalf("selectLinuxShell(withBash) = %q, want /bin/bash", got)
	}

	withoutBash := func(p string) (os.FileInfo, error) {
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

func TestVerifySudoEscalation(t *testing.T) {
	valid := []struct {
		name string
		out  string
	}{
		{
			name: "ubuntu sudo group",
			out: "Matching Defaults entries for lapsadmin on ubuntu:\n" +
				"    env_reset, mail_badpass, use_pty\n\n" +
				"User lapsadmin may run the following commands on ubuntu:\n" +
				"    (ALL : ALL) ALL\n",
		},
		{
			name: "rhel wheel group",
			out: "Matching Defaults entries for lapsadmin on rocky:\n" +
				"    !visiblepw, always_set_home, env_reset\n\n" +
				"User lapsadmin may run the following commands on rocky:\n" +
				"    (ALL) ALL\n",
		},
		{
			name: "nopasswd all",
			out: "User lapsadmin may run the following commands on host:\n" +
				"    (ALL:ALL) NOPASSWD: SETENV: ALL\n",
		},
		{
			name: "targetpw disabled by override",
			out: "Matching Defaults entries for lapsadmin on suse:\n" +
				"    env_reset, targetpw, !targetpw\n\n" +
				"User lapsadmin may run the following commands on suse:\n" +
				"    (ALL) ALL\n",
		},
	}
	for _, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			if err := verifySudoEscalation(tc.out); err != nil {
				t.Fatalf("verifySudoEscalation failed: %v", err)
			}
		})
	}

	invalid := []struct {
		name string
		out  string
	}{
		{
			name: "opensuse targetpw enabled",
			out: "Matching Defaults entries for lapsadmin on opensuse:\n" +
				"    always_set_home, env_reset, targetpw\n\n" +
				"User lapsadmin may run the following commands on opensuse:\n" +
				"    (ALL) ALL\n",
		},
		{
			name: "not allowed",
			out:  "User lapsadmin is not allowed to run sudo on host.\n",
		},
		{
			name: "restricted command only",
			out: "User lapsadmin may run the following commands on host:\n" +
				"    (ALL) /usr/bin/id\n",
		},
		{
			name: "empty output",
			out:  "",
		},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			if err := verifySudoEscalation(tc.out); err == nil {
				t.Fatalf("verifySudoEscalation succeeded for %q, want error", tc.name)
			}
		})
	}
}
