// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

package core

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	"golaps/internal/config"
	"golaps/internal/osmgmt"
	"golaps/internal/password"
	"golaps/internal/vault"
	"golaps/internal/version"
)

func init() {
	vault.SetIntegrationVersion(version.Version)
}

func vaultFailure(err error) error {
	if vault.IsNetworkError(err) {
		return fmt.Errorf("[NETWORK] %w — the vault is unreachable from this device; nothing to fix in LAPS, the run retries on the next check-in once connectivity returns", err)
	}
	return err
}

type candidate struct {
	name  string
	value string
}

// labeledCandidates builds the ordered, deduplicated list of current-password candidates:
// pending -> previous pending -> recorded -> legacy enrollment fallback.
func labeledCandidates(creds *vault.Credentials, legacyPass string) []candidate {
	var out []candidate
	seen := map[string]bool{}
	for _, c := range []candidate{
		{name: "pending", value: creds.PendingPassword},
		{name: "previous pending", value: creds.PreviousPendingPassword},
		{name: "recorded", value: creds.OldPassword},
		{name: "legacy", value: legacyPass},
	} {
		if c.value == "" || seen[c.value] {
			continue
		}
		seen[c.value] = true
		out = append(out, c)
	}
	return out
}

func rotationCandidates(creds *vault.Credentials, legacyPass string) []string {
	var out []string
	for _, c := range labeledCandidates(creds, legacyPass) {
		out = append(out, c.value)
	}
	return out
}

// settleCandidates confirms a live pending password in the vault before staging a new one.
func settleCandidates(ctx context.Context, cfg *config.Config, osMgr osmgmt.Manager, vaultClient vault.Client, creds *vault.Credentials, serialNumber, hostname string) ([]string, error) {
	full := rotationCandidates(creds, cfg.LegacyAdminPass)
	if creds.PendingPassword == "" {
		return full, nil
	}
	stored := labeledCandidates(creds, "")
	verified := map[string]bool{}
	for i, c := range stored {
		ok, err := osMgr.VerifyPassword(ctx, cfg.AdminUser, c.value)
		if errors.Is(err, errors.ErrUnsupported) {
			log.Printf("[INFO] This platform cannot verify a password before the rotation; the rotation tries all %d candidates for %s in order.\n", len(full), cfg.AdminUser)
			return full, nil
		}
		if err != nil {
			if creds.PreviousPendingPassword != "" {
				return nil, fmt.Errorf("could not verify stored password candidates for %s while a previous pending password is still unconfirmed, aborting before staging: %w", cfg.AdminUser, err)
			}
			log.Printf("[WARNING] Could not verify the stored password candidates for %s (%v); the rotation tries remaining candidates in order.\n", cfg.AdminUser, err)
			remaining := []string{}
			for _, v := range full {
				if !verified[v] {
					remaining = append(remaining, v)
				}
			}
			return remaining, nil
		}
		verified[c.value] = true
		if !ok {
			continue
		}
		if c.value == creds.OldPassword {
			log.Printf("[INFO] The %s password candidate (%d of %d) authenticates for %s; the staged copies are stale and the record needs no change.\n", c.name, i+1, len(stored), cfg.AdminUser)
			return []string{c.value}, nil
		}
		log.Printf("[INFO] The %s password candidate (%d of %d) authenticates for %s; recording it as the current password before the next staging.\n", c.name, i+1, len(stored), cfg.AdminUser)
		if err := vaultClient.ConfirmLivePassword(ctx, creds, serialNumber, hostname, cfg.VaultID, cfg.AdminUser, c.value); err != nil {
			return nil, vaultFailure(fmt.Errorf("could not record the verified live password before staging, aborting: %w", err))
		}
		return []string{c.value}, nil
	}
	log.Printf("[WARNING] None of the %d stored password candidates authenticates for %s; the rotation step decides what to do.\n", len(stored), cfg.AdminUser)
	remaining := []string{}
	for _, v := range full {
		if !verified[v] {
			remaining = append(remaining, v)
		}
	}
	return remaining, nil
}

func RunLAPS(ctx context.Context, cfg *config.Config, osMgr osmgmt.Manager, vaultClient vault.Client) error {
	hostname, serialNumber, err := osMgr.GetSystemInfo(ctx)
	if err != nil {
		return fmt.Errorf("could not identify this device, refusing to touch the vault without a serial: %w", err)
	}
	log.Printf("[INFO] Device identified: %s (Serial: %s)\n", hostname, serialNumber)

	log.Printf("[INFO] Scanning the vault for existing credentials for device: %s...\n", serialNumber)
	creds, err := vaultClient.GetCredentials(ctx, serialNumber, cfg.VaultID, cfg.AdminUser)
	if err != nil {
		return vaultFailure(fmt.Errorf("could not read the vault record for %s, refusing to rotate without a working escrow: %w", serialNumber, err))
	}
	if creds.IsMigration {
		log.Printf("[INFO] MIGRATION DETECTED! Config admin: %s, Previous admin in the vault: %s\n", cfg.AdminUser, creds.OldLogin)
	}
	if creds.PendingPassword != "" {
		log.Printf("[WARNING] The vault record carries a staged password from an earlier run that never confirmed — starting the rotation with it; the recorded password is the fallback.\n")
	}

	availableCreds := make(map[string]string)

	if creds.LegacyLogin != "" && creds.LegacyPassword != "" {
		availableCreds[creds.LegacyLogin] = creds.LegacyPassword
	}
	if creds.OldLogin != "" && creds.OldPassword != "" {
		availableCreds[creds.OldLogin] = creds.OldPassword
	}
	if cfg.LegacyAdminPass != "" {
		availableCreds["MDM_FALLBACK_PASS"] = cfg.LegacyAdminPass
	}
	if creds.BridgePassword != "" {
		availableCreds[osmgmt.LegacyBridgeAdmin] = creds.BridgePassword
		log.Printf("[INFO] The vault record carries the escrowed password of the %s bridge admin from an earlier heal.\n", osmgmt.LegacyBridgeAdmin)
	}

	candidates, err := settleCandidates(ctx, cfg, osMgr, vaultClient, creds, serialNumber, hostname)
	if err != nil {
		return err
	}

	newPass, err := password.Generate(cfg.PassLength)
	if err != nil {
		return fmt.Errorf("could not generate a new password: %w", err)
	}
	log.Printf("[INFO] Generated new secure password (Length: %d).\n", cfg.PassLength)

	if err := vaultClient.StagePendingPassword(ctx, creds, serialNumber, hostname, cfg.VaultID, cfg.AdminUser, newPass); err != nil {
		return vaultFailure(fmt.Errorf("could not escrow the new password before rotating, aborting: %w", err))
	}

	osMgr.SetBridgeEscrow(func(c context.Context, pass string) error {
		if err := vaultClient.StageBridgePassword(c, creds, cfg.VaultID, pass); err != nil {
			return err
		}
		availableCreds[osmgmt.LegacyBridgeAdmin] = pass
		return nil
	})

	if err := osMgr.EnsureUserAndChangePassword(ctx, cfg.AdminUser, candidates, newPass); err != nil {
		if errors.Is(err, osmgmt.ErrPolicyRejected) {
			if clearErr := vaultClient.ClearPendingPassword(ctx, creds, cfg.VaultID); clearErr != nil {
				log.Printf("[WARNING] Could not clear the refused pending password: %v — the next run may try it as the current password.\n", clearErr)
			} else {
				log.Println("[INFO] Cleared the refused pending password from the vault record.")
			}
		}
		return fmt.Errorf("OS password rotation failed, aborting the vault sync: %w", err)
	}

	tokenStatus := osMgr.ManageSecureToken(ctx, cfg.AdminUser, newPass, availableCreds)

	log.Println("[INFO] Updating the vault record...")
	if err := vaultClient.UpsertCredentials(ctx, creds, serialNumber, hostname, cfg.VaultID, cfg.AdminUser, newPass, tokenStatus); err != nil {
		return vaultFailure(fmt.Errorf("failed to save to Vault: %w", err))
	}

	if osMgr.CleanupLegacyAdmin(ctx, cfg.AdminUser) && creds.BridgePassword != "" {
		if err := vaultClient.ClearBridgePassword(ctx, creds, cfg.VaultID); err != nil {
			log.Printf("[WARNING] Could not remove the escrowed bridge password from the vault record: %v — harmless, the next cleanup retries.\n", err)
		} else {
			log.Println("[INFO] Removed the escrowed bridge password from the vault record.")
		}
	}

	log.Printf("TOKEN: %s\n", tokenStatus)

	if tokenStatus == osmgmt.TokenStatusDisabledCovered {
		log.Printf("[WARNING] %s finishes without a Secure Token; reported as a covered degradation (a personal recovery key exists locally and the bootstrap token is escrowed). The grant retries on the next check-in.\n", cfg.AdminUser)
		return nil
	}
	if strings.HasPrefix(tokenStatus, osmgmt.TokenStatusDisabledPrefix) {
		return fmt.Errorf("the Secure Token for %s is %s: device has no working FileVault recovery account", cfg.AdminUser, tokenStatus)
	}

	return nil
}
