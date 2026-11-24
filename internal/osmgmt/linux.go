// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

//go:build linux

package osmgmt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

const linuxNetworkProbeTimeout = 10 * time.Second

// LinuxManager manages local administrator accounts on Linux systems.
type LinuxManager struct {
	geteuid  func() int
	readFile func(string) ([]byte, error)
	stat     func(string) (os.FileInfo, error)
	probe    func(ctx context.Context, probeURL string) error
	runCmd   func(ctx context.Context, stdin, secret, name string, args ...string) (string, error)
}

// NewManager returns a LinuxManager configured with live system calls.
func NewManager() Manager {
	return &LinuxManager{
		geteuid:  os.Geteuid,
		readFile: os.ReadFile,
		stat:     os.Stat,
		probe:    probeLinuxEndpoint,
		runCmd:   runLinuxCommand,
	}
}

func runLinuxCommand(ctx context.Context, stdin, secret, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = linuxChildEnv()
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
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err := cmd.Run()
	stdoutText := scrubSecret(strings.TrimSpace(stdoutBuf.String()), secret)
	stderrText := scrubSecret(strings.TrimSpace(stderrBuf.String()), secret)
	if err != nil {
		combined := stdoutText
		if stderrText != "" {
			combined = strings.TrimSpace(combined + "\n" + stderrText)
		}
		errMsg := scrubSecret(err.Error(), secret)
		if combined != "" {
			return stdoutText, fmt.Errorf("%s failed: %s | output: %s", name, errMsg, combined)
		}
		return stdoutText, fmt.Errorf("%s failed: %s", name, errMsg)
	}
	return stdoutText, nil
}

func probeLinuxEndpoint(ctx context.Context, probeURL string) error {
	ctx, cancel := context.WithTimeout(ctx, linuxNetworkProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, probeURL, nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Timeout: linuxNetworkProbeTimeout}).Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// Preflight verifies root privilege and optional vault endpoint reachability.
func (m *LinuxManager) Preflight(ctx context.Context, user, probeURL string) error {
	if euid := m.geteuid(); euid != 0 {
		return fmt.Errorf("GoLAPS must run as root (current euid=%d)", euid)
	}
	if strings.TrimSpace(probeURL) == "" {
		return nil
	}
	log.Printf("[INFO] Checking connection to vault endpoint %s...\n", probeURL)
	if err := m.probe(ctx, probeURL); err != nil {
		log.Printf("[ERROR] Network timeout or no internet connection to %s.\n", probeURL)
		return fmt.Errorf("[NETWORK] vault endpoint %s is unreachable from this device (%v)", probeURL, err)
	}
	return nil
}

// GetSystemInfo returns the hostname and the first valid DMI serial or machine ID.
func (m *LinuxManager) GetSystemInfo(ctx context.Context) (string, string, error) {
	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		hostname = "UnknownHost"
	}
	serial, err := selectLinuxSerial(m.readFile, linuxSerialPaths)
	if err != nil {
		return hostname, "", err
	}
	return hostname, serial, nil
}

// EnsureUserAndChangePassword provisions user, sets the password via chpasswd stdin, unlocks the account, disables expiry, and grants admin group membership.
func (m *LinuxManager) EnsureUserAndChangePassword(ctx context.Context, user string, candidates []string, newPass string) error {
	if err := validateChpasswdInput(user, newPass); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	idBin, err := resolveLinuxTool("id", m.stat)
	if err != nil {
		return err
	}
	usermodBin, err := resolveLinuxTool("usermod", m.stat)
	if err != nil {
		return err
	}
	chpasswdBin, err := resolveLinuxTool("chpasswd", m.stat)
	if err != nil {
		return err
	}
	getentBin, err := resolveLinuxTool("getent", m.stat)
	if err != nil {
		return err
	}

	if _, err := m.runCmd(ctx, "", "", idBin, "--", user); err != nil {
		useraddBin, err := resolveLinuxTool("useradd", m.stat)
		if err != nil {
			return err
		}
		shell := selectLinuxShell(m.stat)
		if _, err := m.runCmd(ctx, "", "", useraddBin, "-m", "-s", shell, "-c", "GoLAPS managed local administrator", "--", user); err != nil {
			return fmt.Errorf("failed to create user %s: %w", user, err)
		}
		log.Printf("[INFO] %s: ACCOUNT_CREATED\n", user)
	}

	payload := user + ":" + newPass + "\n"
	if _, err := m.runCmd(ctx, payload, newPass, chpasswdBin); err != nil {
		return fmt.Errorf("failed to set password for %s: %w", user, err)
	}
	log.Printf("[INFO] %s: PASSWORD_ROTATED\n", user)

	if _, err := m.runCmd(ctx, "", "", usermodBin, "-U", "--", user); err != nil {
		return fmt.Errorf("failed to unlock %s: %w", user, err)
	}

	if chageBin, err := resolveLinuxTool("chage", m.stat); err == nil {
		if _, err := m.runCmd(ctx, "", "", chageBin, "-E", "-1", "-M", "-1", "--", user); err != nil {
			return fmt.Errorf("failed to disable password expiry for %s: %w", user, err)
		}
	}

	adminGroup, err := detectLinuxAdminGroup(func(group string) (string, error) {
		return m.runCmd(ctx, "", "", getentBin, "group", group)
	})
	if err != nil {
		return err
	}
	if _, err := m.runCmd(ctx, "", "", usermodBin, "-aG", adminGroup, "--", user); err != nil {
		return fmt.Errorf("failed to add %s to group %s: %w", user, adminGroup, err)
	}
	log.Printf("[INFO] %s: ADMIN_GRANTED (%s)\n", user, adminGroup)

	return nil
}

func (m *LinuxManager) VerifyPassword(ctx context.Context, user, pass string) (bool, error) {
	return false, errors.ErrUnsupported
}

func (m *LinuxManager) ManageSecureToken(ctx context.Context, targetUser, newPass string, availableCreds map[string]string) string {
	return "N/A (Linux)"
}

func (m *LinuxManager) CleanupLegacyAdmin(ctx context.Context, targetUser string) bool {
	return true
}

func (m *LinuxManager) SetBridgeEscrow(escrow BridgeEscrow) {}

func (m *LinuxManager) DeleteServiceAccountToken(ctx context.Context) error {
	return nil
}
