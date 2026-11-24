// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golaps/internal/config"
	"golaps/internal/core"
	"golaps/internal/osmgmt"
	"golaps/internal/vault"
)

const (
	localLogPath     = "/Library/Logs/golaps.log"
	localLogMaxLines = 2000

	mdmKillLimit     = 60 * time.Minute
	runBudget        = mdmKillLimit - 5*time.Minute
	minRunBudget     = 20 * time.Minute
	startupDelayEnv  = "LAPS_STARTUP_DELAY_SECONDS"
	exitCodeTempFail = 75
)

func runLockExitCode(held bool, err error) int {
	if err != nil {
		return 1
	}
	if held {
		return exitCodeTempFail
	}
	return 0
}

func preflightExitCode(err error) int {
	if err == nil {
		return 0
	}
	if errors.Is(err, osmgmt.ErrSkipRun) {
		return exitCodeTempFail
	}
	return 1
}

func effectiveRunBudget(delayEnv string) time.Duration {
	budget := runBudget
	if secs, err := strconv.Atoi(strings.TrimSpace(delayEnv)); err == nil && secs > 0 {
		budget -= time.Duration(secs) * time.Second
	}
	if budget < minRunBudget {
		budget = minRunBudget
	}
	return budget
}

func tailCapLog(path string) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) <= localLogMaxLines {
		return
	}
	tmpFile, err := os.CreateTemp(filepath.Dir(path), ".golaps-log-*")
	if err != nil {
		return
	}
	tmpName := tmpFile.Name()
	if err := tmpFile.Chmod(0o600); err != nil {
		tmpFile.Close()
		os.Remove(tmpName)
		return
	}
	if _, err := tmpFile.WriteString(strings.Join(lines[len(lines)-localLogMaxLines:], "\n")); err != nil {
		tmpFile.Close()
		os.Remove(tmpName)
		return
	}
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpName)
		return
	}
	if err := os.Rename(tmpName, path); err != nil {
		log.Printf("[WARNING] Could not rotate the local log: %v", err)
		os.Remove(tmpName)
	}
}

func setupLocalLog() func() {
	noop := func() {}
	if runtime.GOOS != "darwin" {
		return noop
	}

	if err := os.MkdirAll(filepath.Dir(localLogPath), 0o755); err != nil {
		log.Printf("[WARNING] Could not create local log directory: %v", err)
		return noop
	}
	tailCapLog(localLogPath)

	f, err := openLogNoFollow(localLogPath)
	if err != nil {
		log.Printf("[WARNING] Could not open local log %s: %v", localLogPath, err)
		return noop
	}
	if err := f.Chmod(0o600); err != nil {
		log.Printf("[WARNING] Could not set the local log mode: %v", err)
	}

	log.SetOutput(io.MultiWriter(os.Stderr, f))
	return func() { f.Close() }
}

var capabilities = []string{
	"recreate-locked",
	"structured-outcome",
	"verified-reset",
	"last-admin-bridge",
	"bt-aware",
	"preflight",
	"conflict-guard",
	"tokenless-in-place",
	"heal-cooldown",
	"bridge-safety",
	"secrets-stdin",
}

func main() {
	if runtime.GOOS != "windows" {
		if err := disableCoreDumps(); err != nil {
			log.Printf("[WARNING] Could not disable core dumps: %v", err)
		}
	}

	if len(os.Args) > 1 && os.Args[1] == "--capabilities" {
		fmt.Println(strings.Join(capabilities, " "))
		return
	}

	// Acquire the run lock before rotating the log so an overlapping process cannot unlink the active log inode.
	lock, held, err := acquireRunLock(runLockPath)
	if code := runLockExitCode(held, err); code != 0 {
		if err != nil {
			log.Printf("[ERROR] Could not take the run lock %s: %v", runLockPath, err)
		} else {
			log.Printf("[INFO] Another GoLAPS run holds %s; this run exits and leaves the rotation to it.", runLockPath)
		}
		os.Exit(code)
	}
	runLock = lock

	closeLocalLog := setupLocalLog()

	fail := func(format string, args ...any) {
		log.Printf(format, args...)
		closeLocalLog()
		os.Exit(1)
	}

	log.Println("====================================================")

	budget := effectiveRunBudget(os.Getenv(startupDelayEnv))
	if budget != runBudget {
		log.Printf("[INFO] The trigger waited %ss before this run; the run budget is %s instead of %s.\n", os.Getenv(startupDelayEnv), budget, runBudget)
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	cfg, err := config.Load(ctx)
	if err != nil {
		fail("[ERROR] Config Init Failed: %v", err)
	}

	// Scrub secret env vars so no child process can inherit them.
	for _, k := range []string{
		"LAPS_VAULT_TOKEN",
		"OP_SERVICE_ACCOUNT_TOKEN",
		"VAULT_TOKEN",
		"LEGACY_ADMIN_PASS",
		"BWS_ACCESS_TOKEN",
		"BW_API_KEY",
		"AZURE_CLIENT_SECRET",
	} {
		os.Unsetenv(k)
	}

	osMgr := osmgmt.NewManager()

	if runtime.GOOS == "darwin" {
		if err := osMgr.DeleteServiceAccountToken(ctx); err != nil {
			log.Printf("[WARNING] Could not shred the vault token from the Keychain: %v", err)
		}
	}

	if err := osMgr.Preflight(ctx, cfg.AdminUser, cfg.ProbeURL); err != nil {
		if code := preflightExitCode(err); code == exitCodeTempFail {
			log.Printf("[INFO] Run skipped: %v", err)
			closeLocalLog()
			os.Exit(code)
		}
		fail("[ERROR] %v", err)
	}

	vClient, err := newVaultClient(ctx, cfg)
	if err != nil {
		fail("[ERROR] Vault Init Failed: %v", err)
	}

	// Scrub AWS runtime credentials once the AWS SDK client has initialized so no child process inherits them.
	os.Unsetenv("AWS_SECRET_ACCESS_KEY")
	os.Unsetenv("AWS_SESSION_TOKEN")

	if err := core.RunLAPS(ctx, cfg, osMgr, vClient); err != nil {
		fail("[ERROR] %v", err)
	}

	closeLocalLog()
}

func newVaultClient(ctx context.Context, cfg *config.Config) (vault.Client, error) {
	switch cfg.VaultType {
	case "onepassword", "1password":
		return vault.New1PasswordClient(ctx, cfg.VaultToken)
	case "hashicorp":
		return vault.NewHashiCorpClient(cfg.HashiCorpAddress, cfg.VaultToken, cfg.HashiCorpPath)
	case "bitwarden":
		return vault.NewBitwardenClient(cfg.BitwardenServerURL, cfg.BitwardenAPIKey, cfg.BitwardenOrgID)
	case "aws":
		return vault.NewAWSClient(cfg.AWSRegion, cfg.AWSProfile)
	case "azure":
		return vault.NewAzureClient(cfg.AzureTenantID, cfg.AzureClientID, cfg.AzureClientSecret, cfg.AzureVaultURL)
	default:
		return nil, fmt.Errorf("unsupported vault type %q", cfg.VaultType)
	}
}
