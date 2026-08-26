// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
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

	// MDM platforms commonly hard-kill a custom script around 60 minutes. The whole run is budgeted below that so LAPS aborts on its own terms — the alternative is being killed mid-vault-write, which loses the rotated password. The budget starts here, at process start: measuring it from the GUI prompt (as the constants in osmgmt used to) ignored everything the run had already spent on the vault list, the rotation and the token-holder scan.
	mdmKillLimit = 60 * time.Minute
	runBudget    = mdmKillLimit - 5*time.Minute
)

func tailCapLog(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return // nothing to cap yet
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) <= localLogMaxLines {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(lines[len(lines)-localLogMaxLines:], "\n")), 0o640); err != nil {
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		log.Printf("[WARNING] Could not rotate the local log: %v", err)
		os.Remove(tmp) // don't leave a copy of the log behind under a second name
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

	// Under MDM this runs as root and the file is writable. On a manual non-root run the MDM/stdout output is still complete and only the local copy is skipped.
	f, err := os.OpenFile(localLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		log.Printf("[WARNING] Could not open local log %s: %v", localLogPath, err)
		return noop
	}

	log.SetOutput(io.MultiWriter(os.Stderr, f))
	return func() { f.Close() }
}

// capabilities is what laps_token.sh asks for instead of comparing version numbers. A hardcoded threshold in the script is wrong exactly once: observed in production, a version gate handed devices over to a binary whose locked-account recreation only landed one release later. An older binary does not know this flag, prints nothing and exits non-zero, which the script reads as "cannot do it" — the safe answer.
var capabilities = []string{
	"recreate-locked",    // heals an account that holds a token but cannot authenticate
	"structured-outcome", // change_password reports the failure class, not just success/failure
	"verified-reset",     // an administrative reset refused by opendirectoryd is never reported as success
	"last-admin-bridge",  // can delete the last admin by bridging the guard with a temporary bridge admin
	"bt-aware",           // a failed token grant on a device with a local PRK + escrowed bootstrap token reports as a warning instead of a failure; the GUI prompt still runs every check-in
}

func main() {
	// Answered before anything else: no config, no vault, no keychain — the script may call this on a device where none of that is set up yet.
	if len(os.Args) > 1 && os.Args[1] == "--capabilities" {
		fmt.Println(strings.Join(capabilities, " "))
		return
	}

	closeLocalLog := setupLocalLog()

	// os.Exit skips deferred calls, so the close is explicit on every path below.
	fail := func(format string, args ...any) {
		log.Printf(format, args...)
		closeLocalLog()
		os.Exit(1)
	}

	log.Println("====================================================")

	ctx, cancel := context.WithTimeout(context.Background(), runBudget)
	defer cancel()

	cfg, err := config.Load(ctx)
	if err != nil {
		fail("[ERROR] Config Init Failed: %v", err)
	}

	osMgr := osmgmt.NewManager()

	if runtime.GOOS == "darwin" {
		// The token now lives in this process's memory; the copy in the System keychain is no longer needed. A failure here is not fatal (laps_token.sh also removes it on exit), but it must not pass unnoticed either.
		if err := osMgr.DeleteServiceAccountToken(ctx); err != nil {
			log.Printf("[WARNING] Could not shred the vault token from the Keychain: %v", err)
		}
	}

	vClient, err := newVaultClient(ctx, cfg)
	if err != nil {
		fail("[ERROR] Vault Init Failed: %v", err)
	}

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
