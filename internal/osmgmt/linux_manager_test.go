// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

//go:build linux

package osmgmt

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
)

type recordedLinuxCmd struct {
	name   string
	args   []string
	stdin  string
	secret string
}

func newTestLinuxManager(
	files map[string]string,
	entries map[string]linuxFakeFileInfo,
	symlinks map[string]string,
	handler func(cmd recordedLinuxCmd) (string, error),
) (*LinuxManager, *[]recordedLinuxCmd) {
	if entries == nil {
		entries = linuxBaseRootTree()
		for _, p := range []string{
			"/usr/sbin/useradd",
			"/usr/sbin/usermod",
			"/usr/sbin/chpasswd",
			"/usr/bin/chage",
			"/usr/bin/getent",
			"/usr/bin/sudo",
			"/bin/bash",
		} {
			entries[p] = linuxFakeFileInfo{name: p[strings.LastIndex(p, "/")+1:], mode: 0o755, uid: 0}
		}
	}
	fs := makeLinuxToolFS(entries, symlinks)
	var calls []recordedLinuxCmd
	m := &LinuxManager{
		geteuid: func() int { return 0 },
		readFile: func(p string) ([]byte, error) {
			v, ok := files[p]
			if !ok {
				return nil, os.ErrNotExist
			}
			return []byte(v), nil
		},
		stat:         fs.stat,
		lstat:        fs.lstat,
		evalSymlinks: fs.evalSymlinks,
		fileOwner:    linuxFileInfoUID,
		probe:        func(ctx context.Context, probeURL string) error { return nil },
		runCmd: func(ctx context.Context, stdin, secret, name string, args ...string) (string, error) {
			rec := recordedLinuxCmd{
				name:   name,
				args:   slices.Clone(args),
				stdin:  stdin,
				secret: secret,
			}
			calls = append(calls, rec)
			return handler(rec)
		},
	}
	return m, &calls
}

func TestLinuxManagerPreflight(t *testing.T) {
	m, _ := newTestLinuxManager(nil, nil, nil, nil)
	m.geteuid = func() int { return 1000 }
	if err := m.Preflight(context.Background(), "lapsadmin", ""); err == nil || !strings.Contains(err.Error(), "must run as root") {
		t.Fatalf("Preflight non-root = %v, want root error", err)
	}

	m.geteuid = func() int { return 0 }
	if err := m.Preflight(context.Background(), "lapsadmin", ""); err != nil {
		t.Fatalf("Preflight root without probeURL failed: %v", err)
	}

	var probed string
	m.probe = func(ctx context.Context, probeURL string) error {
		probed = probeURL
		return nil
	}
	if err := m.Preflight(context.Background(), "lapsadmin", "https://vault.example.com"); err != nil {
		t.Fatalf("Preflight root with reachable probe failed: %v", err)
	}
	if probed != "https://vault.example.com" {
		t.Fatalf("probed = %q, want https://vault.example.com", probed)
	}

	m.probe = func(ctx context.Context, probeURL string) error {
		return errors.New("dial tcp: i/o timeout")
	}
	if err := m.Preflight(context.Background(), "lapsadmin", "https://vault.example.com"); err == nil || !strings.Contains(err.Error(), "[NETWORK]") {
		t.Fatalf("Preflight unreachable = %v, want [NETWORK] error", err)
	}
}

func TestLinuxManagerGetSystemInfo(t *testing.T) {
	files := map[string]string{
		"/sys/class/dmi/id/product_serial": "Asset-1234567890\n",
		"/sys/class/dmi/id/board_serial":   "123456789\n",
		"/sys/class/dmi/id/product_uuid":   "7967FCD2-0CE4-4C0E-AE6C-F66536181D11\n",
	}
	m, _ := newTestLinuxManager(files, nil, nil, nil)
	host, serial, err := m.GetSystemInfo(context.Background())
	if err != nil {
		t.Fatalf("GetSystemInfo failed: %v", err)
	}
	if host == "" {
		t.Fatal("GetSystemInfo returned empty hostname")
	}
	if serial != "7967FCD2-0CE4-4C0E-AE6C-F66536181D11" {
		t.Fatalf("serial = %q, want product_uuid", serial)
	}

	emptyMgr, _ := newTestLinuxManager(map[string]string{}, nil, nil, nil)
	if _, _, err := emptyMgr.GetSystemInfo(context.Background()); err == nil {
		t.Fatal("GetSystemInfo succeeded with no serial sources")
	}
}

func TestLinuxManagerEnsureUserCreatesAndRotatesSafely(t *testing.T) {
	const secret = "S3cr3t:Pass!2026"
	files := map[string]string{
		"/etc/passwd":     "root:x:0:0:root:/root:/bin/bash\n",
		"/etc/login.defs": "UID_MIN 1000\n",
	}
	m, calls := newTestLinuxManager(files, nil, nil, func(cmd recordedLinuxCmd) (string, error) {
		switch cmd.name {
		case "/usr/bin/getent":
			if len(cmd.args) >= 2 && cmd.args[0] == "passwd" {
				return "", errors.New("exit status 2")
			}
			if len(cmd.args) >= 3 && cmd.args[0] == "group" && cmd.args[2] == "sudo" {
				return "sudo:x:27:", nil
			}
			return "", errors.New("exit status 2")
		case "/usr/bin/sudo":
			return "User lapsadmin may run the following commands on host:\n    (ALL : ALL) ALL\n", nil
		default:
			return "", nil
		}
	})

	if err := m.EnsureUserAndChangePassword(context.Background(), "lapsadmin", nil, secret); err != nil {
		t.Fatalf("EnsureUserAndChangePassword failed: %v", err)
	}

	var sawUseradd, sawChpasswd, sawUnlock, sawChage, sawGroupAdd, sawSudoVerify bool
	for _, c := range *calls {
		for _, arg := range c.args {
			if strings.Contains(arg, secret) {
				t.Fatalf("password leaked into argv of %s: %v", c.name, c.args)
			}
		}
		switch c.name {
		case "/usr/sbin/useradd":
			sawUseradd = true
			want := []string{"-m", "-s", "/bin/bash", "-c", "GoLAPS managed", "--", "lapsadmin"}
			if !slices.Equal(c.args, want) {
				t.Fatalf("useradd args = %v, want %v", c.args, want)
			}
		case "/usr/sbin/chpasswd":
			sawChpasswd = true
			if len(c.args) != 0 {
				t.Fatalf("chpasswd must take no argv, got %v", c.args)
			}
			if c.stdin != "lapsadmin:"+secret+"\n" {
				t.Fatalf("chpasswd stdin mismatch")
			}
			if c.secret != secret {
				t.Fatalf("chpasswd secret scrub token was not passed")
			}
		case "/usr/sbin/usermod":
			if slices.Equal(c.args, []string{"-U", "--", "lapsadmin"}) {
				sawUnlock = true
			}
			if slices.Equal(c.args, []string{"-aG", "sudo", "--", "lapsadmin"}) {
				sawGroupAdd = true
			}
		case "/usr/bin/chage":
			sawChage = true
			want := []string{"-E", "-1", "-M", "-1", "--", "lapsadmin"}
			if !slices.Equal(c.args, want) {
				t.Fatalf("chage args = %v, want %v", c.args, want)
			}
		case "/usr/bin/sudo":
			sawSudoVerify = true
			want := []string{"-l", "-U", "lapsadmin"}
			if !slices.Equal(c.args, want) {
				t.Fatalf("sudo args = %v, want %v", c.args, want)
			}
		}
	}
	if !sawUseradd || !sawChpasswd || !sawUnlock || !sawChage || !sawGroupAdd || !sawSudoVerify {
		t.Fatalf("missing expected commands: useradd=%v chpasswd=%v unlock=%v chage=%v group=%v sudo=%v",
			sawUseradd, sawChpasswd, sawUnlock, sawChage, sawGroupAdd, sawSudoVerify)
	}
}

func TestLinuxManagerRejectsExternalNSSAccount(t *testing.T) {
	files := map[string]string{
		"/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
	}
	m, calls := newTestLinuxManager(files, nil, nil, func(cmd recordedLinuxCmd) (string, error) {
		if cmd.name == "/usr/bin/getent" && slices.Equal(cmd.args, []string{"passwd", "--", "corpadmin"}) {
			return "corpadmin:x:50001:50001:Corporate LDAP Admin:/home/corpadmin:/bin/bash", nil
		}
		t.Fatalf("unexpected command after NSS hit: %s %v", cmd.name, cmd.args)
		return "", nil
	})

	err := m.EnsureUserAndChangePassword(context.Background(), "corpadmin", nil, "StrongPass!1")
	if err == nil || !strings.Contains(err.Error(), "external NSS account") {
		t.Fatalf("err = %v, want external NSS rejection", err)
	}
	if len(*calls) != 1 {
		t.Fatalf("expected only getent passwd lookup, got %d calls", len(*calls))
	}
}

func TestLinuxManagerRejectsUnsafeExistingLocalAccounts(t *testing.T) {
	passwd := strings.Join([]string{
		"toor:x:0:0:GoLAPS managed:/root:/bin/bash",
		"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
		"sysacct:x:999:999:GoLAPS managed:/home/sysacct:/bin/bash",
		"employee:x:1005:1005:Regular User:/home/employee:/bin/bash",
	}, "\n")
	files := map[string]string{
		"/etc/passwd":     passwd,
		"/etc/login.defs": "UID_MIN 1000\n",
	}

	for _, user := range []string{"toor", "www-data", "sysacct", "employee"} {
		t.Run(user, func(t *testing.T) {
			m, calls := newTestLinuxManager(files, nil, nil, func(cmd recordedLinuxCmd) (string, error) {
				t.Fatalf("no OS command may run for rejected local user %s: %s %v", user, cmd.name, cmd.args)
				return "", nil
			})
			if err := m.EnsureUserAndChangePassword(context.Background(), user, nil, "StrongPass!1"); err == nil {
				t.Fatalf("EnsureUserAndChangePassword(%s) succeeded, want error", user)
			}
			if len(*calls) != 0 {
				t.Fatalf("unexpected commands ran: %v", *calls)
			}
		})
	}
}

func TestLinuxManagerRejectsMissingOrBlockedSudo(t *testing.T) {
	files := map[string]string{
		"/etc/passwd":     "lapsadmin:x:1001:1001:GoLAPS managed:/home/lapsadmin:/bin/bash\n",
		"/etc/login.defs": "UID_MIN 1000\n",
	}

	t.Run("missing sudo binary", func(t *testing.T) {
		entries := linuxBaseRootTree()
		for _, p := range []string{"/usr/sbin/usermod", "/usr/sbin/chpasswd", "/usr/bin/getent"} {
			entries[p] = linuxFakeFileInfo{name: p[strings.LastIndex(p, "/")+1:], mode: 0o755, uid: 0}
		}
		m, _ := newTestLinuxManager(files, entries, nil, func(cmd recordedLinuxCmd) (string, error) {
			if cmd.name == "/usr/bin/getent" && len(cmd.args) >= 3 && cmd.args[0] == "group" && cmd.args[2] == "sudo" {
				return "sudo:x:27:", nil
			}
			if cmd.name == "/usr/bin/getent" && len(cmd.args) >= 3 && cmd.args[0] == "passwd" {
				return "lapsadmin:x:1001:1001:GoLAPS managed:/home/lapsadmin:/bin/bash", nil
			}
			return "", nil
		})
		err := m.EnsureUserAndChangePassword(context.Background(), "lapsadmin", nil, "StrongPass!1")
		if err == nil || !strings.Contains(err.Error(), "sudo is required") {
			t.Fatalf("err = %v, want missing sudo error", err)
		}
	})

	t.Run("opensuse targetpw blocks escalation", func(t *testing.T) {
		m, _ := newTestLinuxManager(files, nil, nil, func(cmd recordedLinuxCmd) (string, error) {
			if cmd.name == "/usr/bin/getent" && len(cmd.args) >= 3 && cmd.args[0] == "group" && cmd.args[2] == "wheel" {
				return "wheel:x:10:", nil
			}
			if cmd.name == "/usr/bin/getent" && len(cmd.args) >= 3 && cmd.args[0] == "passwd" {
				return "lapsadmin:x:1001:1001:GoLAPS managed:/home/lapsadmin:/bin/bash", nil
			}
			if cmd.name == "/usr/bin/getent" {
				return "", errors.New("exit status 2")
			}
			if cmd.name == "/usr/bin/sudo" {
				return "Matching Defaults entries for lapsadmin on suse:\n    env_reset, targetpw\n\nUser lapsadmin may run the following commands on suse:\n    (ALL) ALL\n", nil
			}
			return "", nil
		})
		err := m.EnsureUserAndChangePassword(context.Background(), "lapsadmin", nil, "StrongPass!1")
		if err == nil || !strings.Contains(err.Error(), "targetpw") {
			t.Fatalf("err = %v, want targetpw error", err)
		}
	})
}

func TestLinuxManagerScrubsSecretOnChpasswdFailure(t *testing.T) {
	const secret = "UltraSecret!999"
	files := map[string]string{
		"/etc/passwd":     "lapsadmin:x:1001:1001:GoLAPS managed:/home/lapsadmin:/bin/bash\n",
		"/etc/login.defs": "UID_MIN 1000\n",
	}
	m, _ := newTestLinuxManager(files, nil, nil, func(cmd recordedLinuxCmd) (string, error) {
		if cmd.name == "/usr/bin/getent" {
			return "lapsadmin:x:1001:1001:GoLAPS managed:/home/lapsadmin:/bin/bash", nil
		}
		if cmd.name == "/usr/sbin/chpasswd" {
			rawErr := fmt.Sprintf("chpasswd rejected password %s", secret)
			return "", errors.New(scrubSecret(rawErr, cmd.secret))
		}
		return "", nil
	})

	err := m.EnsureUserAndChangePassword(context.Background(), "lapsadmin", nil, secret)
	if err == nil {
		t.Fatal("expected chpasswd error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("secret leaked in error: %v", err)
	}
	if !strings.Contains(err.Error(), "[REDACTED]") {
		t.Fatalf("expected [REDACTED] in error: %v", err)
	}
}

func TestRunLinuxCommandScrubsSecretOutput(t *testing.T) {
	const secret = "ChildSecret!42"
	out, err := runLinuxCommand(context.Background(), "", secret, "/bin/sh", "-c", "printf 'out:%s' "+secret+"; printf 'err:%s' "+secret+" >&2; exit 1")
	if err == nil {
		t.Fatal("expected command failure")
	}
	if strings.Contains(out, secret) || strings.Contains(err.Error(), secret) {
		t.Fatalf("secret leaked in stdout=%q err=%v", out, err)
	}
	if !strings.Contains(out, "[REDACTED]") || !strings.Contains(err.Error(), "[REDACTED]") {
		t.Fatalf("expected redacted output, got stdout=%q err=%v", out, err)
	}
}
