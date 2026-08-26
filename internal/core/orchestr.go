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
)

// vaultFailure tags connectivity failures so an MDM log reader can tell "the device is offline / on vacation, wait" apart from a LAPS problem at a glance.
func vaultFailure(err error) error {
	if vault.IsNetworkError(err) {
		return fmt.Errorf("[NETWORK] %w — the vault is unreachable from this device; nothing to fix in LAPS, the run retries on the next check-in once connectivity returns", err)
	}
	return err
}

func RunLAPS(ctx context.Context, cfg *config.Config, osMgr osmgmt.Manager, vaultClient vault.Client) error {
	hostname, serialNumber := osMgr.GetSystemInfo(ctx)
	log.Printf("[INFO] Device identified: %s (Serial: %s)\n", hostname, serialNumber)

	log.Printf("[INFO] Scanning the vault for existing credentials for device: %s...\n", serialNumber)
	creds, err := vaultClient.GetCredentials(ctx, serialNumber, cfg.VaultID, cfg.AdminUser)
	if err != nil {
		// Aborting here is deliberate. A vault we cannot read is very likely a vault we cannot write either, and rotating the password without a reliable escrow is what leaves a device with a password nobody knows. The MDM retries on the next check-in.
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

	newPass, err := password.Generate(cfg.PassLength)
	if err != nil {
		return fmt.Errorf("could not generate a new password: %w", err)
	}
	log.Printf("[INFO] Generated new secure password (Length: %d).\n", cfg.PassLength)

	// Escrow before rotating, never after: the rotation is irreversible and the vault holds the only copy of the result. A vault write attempted only afterwards leaves no way back if it fails, and this also proves the service account still has write access before the device is touched at all.
	if err := vaultClient.StagePendingPassword(ctx, creds, serialNumber, hostname, cfg.VaultID, cfg.AdminUser, newPass); err != nil {
		return vaultFailure(fmt.Errorf("could not escrow the new password before rotating, aborting: %w", err))
	}

	// A surviving staged password means the previous run died between rotating the device and confirming the vault — in every observed failure of that kind (vault write contention) the device already held the staged value. Starting with it spares a doomed attempt with the stale recorded password, which is exactly what feeds the failed-auth counter.
	passForReset := creds.PendingPassword
	altForReset := creds.OldPassword
	if passForReset == "" {
		passForReset, altForReset = creds.OldPassword, ""
	}
	if passForReset == "" {
		passForReset = cfg.LegacyAdminPass
	}
	if altForReset == passForReset {
		altForReset = ""
	}

	if err := osMgr.EnsureUserAndChangePassword(ctx, cfg.AdminUser, passForReset, altForReset, newPass); err != nil {
		// A policy-rejected password provably never reached the device, so the staged copy must not survive: left in place, the next run's passForReset fallback tries the refused value as the current password and escalates a healthy account to recreation.
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

	// The vault write above deliberately happens first: the rotated password must be recorded even when the token grant failed, otherwise the device becomes unreachable. But the run itself is NOT a success — without a Secure Token the account cannot unlock FileVault, and exiting 0 here is what made the MDM report "Pass" for devices left with no working recovery account. The one exception: the rotation succeeded, the password is escrowed, and the failed token grant already retried its prompt — with a local PRK and an escrowed bootstrap token the device is degraded, not broken, so it reports a warning instead of sitting permanently red while the grant keeps retrying every check-in.
	if tokenStatus == osmgmt.TokenStatusDisabledCovered {
		log.Printf("[WARNING] %s finishes without a Secure Token; reported as a covered degradation (a personal recovery key exists locally and the bootstrap token is escrowed). The grant retries on the next check-in.\n", cfg.AdminUser)
		return nil
	}
	if strings.HasPrefix(tokenStatus, osmgmt.TokenStatusDisabledPrefix) {
		return fmt.Errorf("the Secure Token for %s is %s: device has no working FileVault recovery account", cfg.AdminUser, tokenStatus)
	}

	return nil
}
