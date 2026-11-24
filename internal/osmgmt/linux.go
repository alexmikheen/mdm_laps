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
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const linuxNetworkProbeTimeout = 10 * time.Second

// LinuxManager manages local administrator accounts on Linux systems.
type LinuxManager struct {
	geteuid      func() int
	readFile     func(string) ([]byte, error)
	stat         func(string) (os.FileInfo, error)
	lstat        func(string) (os.FileInfo, error)
	evalSymlinks func(string) (string, error)
	fileOwner    func(os.FileInfo) (uint32, bool)
	probe        func(ctx context.Context, probeURL string) error
	runCmd       func(ctx context.Context, stdin, secret, name string, args ...string) (string, error)
}

// NewManager returns a LinuxManager configured with live system calls.
func NewManager() Manager {
	return &LinuxManager{
		geteuid:      os.Geteuid,
		readFile:     os.ReadFile,
		stat:         os.Stat,
		lstat:        os.Lstat,
		evalSymlinks: filepath.EvalSymlinks,
		fileOwner:    linuxFileInfoUID,
		probe:        probeLinuxEndpoint,
		runCmd:       runLinuxCommand,
	}
}

func linuxFileInfoUID(info os.FileInfo) (uint32, bool) {
	if st, ok := info.Sys().(*syscall.Stat_t); ok && st != nil {
		return st.Uid, true
	}
	if owner, ok := info.(linuxFileOwner); ok {
		return owner.OwnerUID(), true
	}
	return 0, false
}

func (m *LinuxManager) resolveTool(name string) (string, error) {
	return resolveLinuxTool(name, linuxToolFS{
		stat:         m.stat,
		lstat:        m.lstat,
		evalSymlinks: m.evalSymlinks,
		fileOwner:    m.fileOwner,
	})
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

// EnsureUserAndChangePassword provisions a local managed user, rotates its password via chpasswd stdin, unlocks it, disables expiry, grants admin membership, and verifies sudo escalation.
func (m *LinuxManager) EnsureUserAndChangePassword(ctx context.Context, user string, candidates []string, newPass string) error {
	if err := validateChpasswdInput(user, newPass); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	usermodBin, err := m.resolveTool("usermod")
	if err != nil {
		return err
	}
	chpasswdBin, err := m.resolveTool("chpasswd")
	if err != nil {
		return err
	}
	getentBin, err := m.resolveTool("getent")
	if err != nil {
		return err
	}

	passwdData, err := m.readFile(linuxPasswdPath)
	if err != nil {
		return fmt.Errorf("could not read %s: %w", linuxPasswdPath, err)
	}
	localEntry, localExists := lookupLocalPasswd(string(passwdData), user)

	if localExists {
		uidMin := defaultLinuxUIDMin
		if defsData, err := m.readFile(linuxLoginDefsPath); err == nil {
			uidMin = parseLoginDefsUIDMin(string(defsData))
		}
		if err := validateManagedLocalAccount(localEntry, uidMin); err != nil {
			return err
		}
		if nssOut, err := m.runCmd(ctx, "", "", getentBin, "passwd", "--", user); err == nil {
			if nssEntry, ok := lookupLocalPasswd(nssOut, user); ok && nssEntry.UID != localEntry.UID {
				return fmt.Errorf("refusing to manage account %q: NSS uid %d conflicts with local uid %d", user, nssEntry.UID, localEntry.UID)
			}
		}
	} else {
		if nssOut, err := m.runCmd(ctx, "", "", getentBin, "passwd", "--", user); err == nil {
			if _, ok := lookupLocalPasswd(nssOut, user); ok {
				return fmt.Errorf("refusing to manage external NSS account %q (not found in %s)", user, linuxPasswdPath)
			}
		}
		useraddBin, err := m.resolveTool("useradd")
		if err != nil {
			return err
		}
		shell := selectLinuxShell(m.stat)
		if _, err := m.runCmd(ctx, "", "", useraddBin, "-m", "-s", shell, "-c", linuxManagedGECOS, "--", user); err != nil {
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

	if chageBin, err := m.resolveTool("chage"); err == nil {
		if _, err := m.runCmd(ctx, "", "", chageBin, "-E", "-1", "-M", "-1", "--", user); err != nil {
			return fmt.Errorf("failed to disable password expiry for %s: %w", user, err)
		}
	}

	adminGroup, err := detectLinuxAdminGroup(func(group string) (string, error) {
		return m.runCmd(ctx, "", "", getentBin, "group", "--", group)
	})
	if err != nil {
		return err
	}
	if _, err := m.runCmd(ctx, "", "", usermodBin, "-aG", adminGroup, "--", user); err != nil {
		return fmt.Errorf("failed to add %s to group %s: %w", user, adminGroup, err)
	}

	sudoBin, err := m.resolveTool("sudo")
	if err != nil {
		return fmt.Errorf("sudo is required to verify admin escalation for %s: %w", user, err)
	}
	sudoOut, err := m.runCmd(ctx, "", "", sudoBin, "-l", "-U", user)
	if err != nil {
		return fmt.Errorf("sudo privilege verification failed for %s: %w", user, err)
	}
	if err := verifySudoEscalation(sudoOut); err != nil {
		return fmt.Errorf("user %s does not have effective sudo escalation: %w", user, err)
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
