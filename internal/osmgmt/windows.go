// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

//go:build windows

package osmgmt

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
	"unicode/utf16"
)

type WindowsManager struct{}

func NewManager() Manager {
	return &WindowsManager{}
}

func psEncode(script string) string {
	var buf bytes.Buffer
	for _, unit := range utf16.Encode([]rune(script)) {
		buf.WriteByte(byte(unit))
		buf.WriteByte(byte(unit >> 8))
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func runPowerShell(ctx context.Context, script, stdin string, extraEnv ...string) (string, error) {
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		return "", fmt.Errorf("SystemRoot is not set; cannot locate powershell.exe")
	}
	cmd := exec.CommandContext(ctx, powerShellPath(systemRoot),
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-EncodedCommand", psEncode(script))
	cmd.Env = powerShellEnv(systemRoot, os.Getenv("TEMP"), extraEnv...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin + "\n")
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err := cmd.Run()
	stdoutText := strings.TrimSpace(stdoutBuf.String())
	stderrText := strings.TrimSpace(stderrBuf.String())
	if stdin != "" {
		stdoutText = strings.ReplaceAll(stdoutText, stdin, "[REDACTED]")
		stderrText = strings.ReplaceAll(stderrText, stdin, "[REDACTED]")
	}
	if err != nil {
		combined := stdoutText
		if stderrText != "" {
			combined = strings.TrimSpace(combined + "\n" + stderrText)
		}
		return stdoutText, fmt.Errorf("powershell failed: %w | output: %s", err, combined)
	}
	if stderrText != "" {
		log.Printf("[INFO] PowerShell stderr: %s\n", stderrText)
	}
	return stdoutText, nil
}

func (w *WindowsManager) GetSystemInfo(ctx context.Context) (string, string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "UnknownHost"
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	out, err := runPowerShell(ctx, serialScript, "")
	if err != nil {
		return hostname, "", fmt.Errorf("could not read the machine serial: %w", err)
	}
	serial, err := validateWindowsSerial(out)
	if err != nil {
		return hostname, "", err
	}
	return hostname, serial, nil
}

func (w *WindowsManager) EnsureUserAndChangePassword(ctx context.Context, user string, candidates []string, newPass string) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	out, err := runPowerShell(ctx, ensureAccountScript, newPass, "LAPS_TARGET_USER="+user)
	if err != nil {
		return fmt.Errorf("failed to provision %s: %w", user, err)
	}
	if !scriptReportsSuccess(out) {
		return fmt.Errorf("provisioning %s did not complete: %s", user, out)
	}

	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); line != "" && line != resultMarker {
			log.Printf("[INFO] %s: %s\n", user, line)
		}
	}

	return nil
}

func (w *WindowsManager) VerifyPassword(ctx context.Context, user, pass string) (bool, error) {
	return false, errors.ErrUnsupported
}

func (w *WindowsManager) ManageSecureToken(ctx context.Context, targetUser, newPass string, availableCreds map[string]string) string {
	return "N/A (Windows)"
}

func (w *WindowsManager) Preflight(ctx context.Context, user, probeURL string) error { return nil }

func (w *WindowsManager) CleanupLegacyAdmin(ctx context.Context, targetUser string) bool {
	return true
}

func (w *WindowsManager) SetBridgeEscrow(escrow BridgeEscrow) {}

func (w *WindowsManager) DeleteServiceAccountToken(ctx context.Context) error {
	return nil
}
