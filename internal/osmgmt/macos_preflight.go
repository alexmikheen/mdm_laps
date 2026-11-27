// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

//go:build darwin

package osmgmt

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	batteryAbortPercent = 10
	onePasswordProbeURL = "https://my.1password.com"
	networkProbeTimeout = 10 * time.Second

	// Failed logins at or above conflictThreshold signal an external process authenticating as the account.
	conflictThreshold = 5

	// healStatePath tracks the last account recreation to stop repeated heal loops.
	healStatePath   = "/var/db/golaps/last_heal"
	healCooldown    = 7 * 24 * time.Hour
	healOverrideEnv = "LAPS_ALLOW_REHEAL"

	nativeLAPSLogPredicate = `process == "kandji-library-manager" AND category == "LAPS"`
)

var (
	failedLoginCountRe   = regexp.MustCompile(`<key>failedLoginCount</key>\s*<integer>(\d+)</integer>`)
	passwordLastSetRe    = regexp.MustCompile(`<key>passwordLastSetTime</key>\s*<real>([0-9.]+)</real>`)
	batteryPercentRe     = regexp.MustCompile(`([0-9]+)%`)
	nativeLAPSRotatingRe = regexp.MustCompile(`\[LAPS\] (.+?): rotating \d+ account`)
)

// Preflight checks battery, network, and binary integrity before any account or vault write.
func (m *MacOSManager) Preflight(ctx context.Context, user, probeURL string) error {
	if err := m.batteryCheck(ctx); err != nil {
		return err
	}
	if err := m.networkCheck(ctx, probeURL); err != nil {
		return err
	}
	for _, path := range []string{helperPath, authWindowPath} {
		if err := m.trustedBinary(path); err != nil {
			return fmt.Errorf("integrity check failed before the run touched the account or the vault: %w", err)
		}
	}
	if err := m.repairServiceAccount(ctx, user); err != nil {
		return err
	}
	m.clearBridgeCounter(ctx)
	return nil
}

func (m *MacOSManager) batteryCheck(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := m.run.Run(ctx, "", toolPmset, "-g", "batt")
	if err != nil {
		log.Printf("[INFO] Could not read the battery state (%v); continuing.\n", err)
		return nil
	}
	info := strings.ToLower(string(out))
	if !strings.Contains(info, "battery power") && !strings.Contains(info, "discharging") {
		return nil
	}
	match := batteryPercentRe.FindStringSubmatch(info)
	if match == nil {
		return nil
	}
	pct, err := strconv.Atoi(match[1])
	if err != nil || pct >= batteryAbortPercent {
		return nil
	}
	log.Printf("[WARNING] Laptop is on battery power and below %d%% (%d%%).\n", batteryAbortPercent, pct)
	log.Println("[INFO] Aborting LAPS rotation to prevent state desync in case of sudden shutdown.")
	return fmt.Errorf("%w: on battery power at %d%%", ErrSkipRun, pct)
}

func (m *MacOSManager) networkCheck(ctx context.Context, probeURL string) error {
	if strings.TrimSpace(probeURL) == "" {
		return nil
	}
	log.Printf("[INFO] Checking connection to vault endpoint %s...\n", probeURL)
	if err := m.probe(ctx, probeURL); err != nil {
		log.Printf("[ERROR] Network timeout or no internet connection to %s.\n", probeURL)
		log.Println("[INFO] Exiting early; will retry on next MDM check-in.")
		return fmt.Errorf("[NETWORK] vault endpoint %s is unreachable from this device (%v) — nothing to fix in LAPS, the run retries on the next check-in once connectivity returns", probeURL, err)
	}
	return nil
}

func probeVaultEndpoint(ctx context.Context, probeURL string) error {
	ctx, cancel := context.WithTimeout(ctx, networkProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, probeURL, nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Timeout: networkProbeTimeout}).Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// repairServiceAccount checks for auth conflicts, restores admin membership, and clears per-user password blocks.
func (m *MacOSManager) repairServiceAccount(ctx context.Context, user string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()

	exists, err := m.userAccountExists(ctx, user)
	if err != nil {
		return err
	}
	if !exists {
		return nil // EnsureUserAndChangePassword creates the account
	}

	count := m.failedLoginCount(ctx, user)
	if count > 0 {
		log.Printf("[WARNING] %s has %d recorded failed login attempt(s) — clearing.\n", user, count)
	}
	if count >= conflictThreshold {
		return m.conflictError(ctx, user, count)
	}
	m.clearFailedLoginCounter(ctx, user)

	// Restore admin membership in case a privilege-management tool demoted the service account.
	if _, err := m.run.Run(ctx, "", toolDseditgroup, "-o", "checkmember", "-m", user, "admin"); err != nil {
		log.Printf("[WARNING] %s is not in the admin group (Admin By Request cleanup?) — re-adding. Recurring on this device means %s must go into AbR ExcludedAccounts.\n", user, user)
		if out, err := m.run.Run(ctx, "", toolDseditgroup, "-o", "edit", "-a", user, "-t", "user", "admin"); err != nil {
			log.Printf("[ERROR] Could not re-add %s to the admin group: %v | %s\n", user, err, strings.TrimSpace(string(out)))
		}
	}

	verdict := m.pwpolicyVerdict(ctx, user)
	log.Printf("[INFO] pwpolicy verdict for %s: %s\n", user, verdict)

	if strings.Contains(verdict, "until password is changed") {
		log.Printf("[REPAIR] legacy per-user policy: %s\n", m.evidence(ctx, 300, toolPwpolicy, "-u", user, "-getpolicy"))
		log.Printf("[REPAIR] PasswordPolicyOptions: %s\n", m.evidence(ctx, 300, toolDscl, ".", "-read", "/Users/"+user, "PasswordPolicyOptions"))
		log.Printf("[REPAIR] GLOBAL account policies: %s\n", m.evidence(ctx, 900, toolPwpolicy, "-getaccountpolicies"))
		policyData := m.evidence(ctx, 800, toolDscl, ".", "-read", "/Users/"+user, "accountPolicyData")
		log.Printf("[REPAIR] accountPolicyData (full): %s\n", policyData)
		log.Printf("[REPAIR] AuthenticationAuthority: %s\n", m.evidence(ctx, 300, toolDscl, ".", "-read", "/Users/"+user, "AuthenticationAuthority"))
		if match := passwordLastSetRe.FindStringSubmatch(policyData); match != nil {
			if epoch, err := strconv.ParseFloat(match[1], 64); err == nil {
				log.Printf("[REPAIR] passwordLastSetTime: %s\n", time.Unix(int64(epoch), 0).Format("2006-01-02 15:04:05"))
			}
		}

		// Clear per-user change-required policies only and leave global or profile policies unchanged.
		log.Printf("[REPAIR] setpolicy output: %s\n", m.evidence(ctx, 200, toolPwpolicy, "-u", user, "-setpolicy", "newPasswordRequired=0 maxMinutesUntilChangePassword=0"))
		verdict = m.pwpolicyVerdict(ctx, user)
		log.Printf("[REPAIR] verdict after legacy-policy reset: %s\n", verdict)

		if authenticationBlocked(verdict) {
			log.Printf("[REPAIR] clearaccountpolicies output: %s\n", m.evidence(ctx, 200, toolPwpolicy, "-u", user, "-clearaccountpolicies"))
			verdict = m.pwpolicyVerdict(ctx, user)
			log.Printf("[REPAIR] verdict after clearing per-user account policies: %s\n", verdict)
		}
	}

	if authenticationBlocked(verdict) {
		log.Printf("[WARNING] %s is still blocked after every soft repair — the rotation step escalates to account recreation. The console user may get the Admin By Request token prompt.\n", user)
	}
	return nil
}

// clearBridgeCounter clears failed logins on laps-bridge below conflictThreshold, or preserves the counter as evidence.
func (m *MacOSManager) clearBridgeCounter(ctx context.Context) {
	exists, err := m.userAccountExists(ctx, LegacyBridgeAdmin)
	if err != nil || !exists {
		return
	}
	count := m.failedLoginCount(ctx, LegacyBridgeAdmin)
	if count >= conflictThreshold {
		log.Printf("[CONFLICT] %s has %d recorded failed logins since the last run; the counter is kept as evidence and not cleared\n", LegacyBridgeAdmin, count)
		return
	}
	if count > 0 {
		log.Printf("[WARNING] %s has %d recorded failed login attempt(s) — clearing. Earlier runs spent them with stored passwords that do not fit this account.\n", LegacyBridgeAdmin, count)
	}
	m.clearFailedLoginCounter(ctx, LegacyBridgeAdmin)
}

// Matches both Apple phrasings for a blocked account in pwpolicy output.
func authenticationBlocked(verdict string) bool {
	return strings.Contains(verdict, "not") && strings.Contains(verdict, "allowed to authenticate")
}

func (m *MacOSManager) pwpolicyVerdict(ctx context.Context, user string) string {
	out, _ := m.run.Run(ctx, "", toolPwpolicy, "-u", user, "authentication-allowed")
	return strings.TrimSpace(strings.ReplaceAll(string(out), "\n", " "))
}

func (m *MacOSManager) evidence(ctx context.Context, limit int, name string, args ...string) string {
	out, _ := m.run.Run(ctx, "", name, args...)
	text := strings.TrimSpace(strings.ReplaceAll(string(out), "\n", " "))
	if len(text) > limit {
		return text[:limit]
	}
	return text
}

// failedLoginCount returns -1 when accountPolicyData cannot be read.
func (m *MacOSManager) failedLoginCount(ctx context.Context, user string) int {
	out, err := m.run.Run(ctx, "", toolDscl, ".", "-read", "/Users/"+user, "accountPolicyData")
	if err != nil {
		return -1
	}
	match := failedLoginCountRe.FindStringSubmatch(string(out))
	if match == nil {
		return 0
	}
	n, err := strconv.Atoi(match[1])
	if err != nil {
		return -1
	}
	return n
}

// clearFailedLoginCounter deletes failedLoginCount and failedLoginTimestamp as root without spending an auth attempt.
func (m *MacOSManager) clearFailedLoginCounter(ctx context.Context, user string) {
	for _, key := range []string{"failedLoginCount", "failedLoginTimestamp"} {
		if out, err := m.run.Run(ctx, "", toolDscl, ".", "-deletepl", "/Users/"+user, "accountPolicyData", key); err != nil {
			_ = out
		}
	}
}

func (m *MacOSManager) conflictError(ctx context.Context, user string, count int) error {
	item, attempts := m.nativeLAPSActivity(ctx)
	if item != "" {
		log.Printf("[CONFLICT] native GoLAPS item %q rotated %s %d time(s) in the last 24h — it is the source of the %d failed authentications.\n", item, user, attempts, count)
		return fmt.Errorf("%w native GoLAPS item %q is rotating %s on this device (%d failed authentications, %d native rotation attempts in 24h). Not clearing the counter and not recreating the account: unassign that library item from this device, then LAPS recovers on the next check-in", ErrConflict, item, user, count, attempts)
	}
	log.Printf("[CONFLICT] %s has %d failed authentications since the last run and no native GoLAPS activity explains them.\n", user, count)
	return fmt.Errorf("%w %s has %d failed authentications since the last run from an unknown process — refusing to rotate or recreate (either would only lock it again). Find what authenticates as %s: /usr/bin/log show --last 1d --predicate 'process == \"opendirectoryd\"' | grep 'Failed SecureToken authentication'", ErrConflict, user, count, user)
}

func (m *MacOSManager) nativeLAPSActivity(ctx context.Context) (item string, attempts int) {
	ctx, cancel := withReserve(ctx, 90*time.Second, vaultWriteReserve)
	defer cancel()
	out, err := m.run.Run(ctx, "", toolLog, "show", "--last", "1d", "--style", "compact", "--predicate", nativeLAPSLogPredicate)
	if err != nil {
		log.Printf("[INFO] Could not read the MDM agent's LAPS activity from the unified log: %v\n", err)
		return "", 0
	}
	for _, line := range strings.Split(string(out), "\n") {
		if match := nativeLAPSRotatingRe.FindStringSubmatch(line); match != nil {
			item = match[1]
			attempts++
		}
	}
	return item, attempts
}

func (m *MacOSManager) lastHeal(user string) (time.Time, bool) {
	data, err := os.ReadFile(m.healStatePath)
	if err != nil {
		return time.Time{}, false
	}
	fields := strings.Fields(string(data))
	if len(fields) != 2 || fields[1] != user {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, fields[0])
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func (m *MacOSManager) recordHeal(user string) {
	if err := os.MkdirAll(filepath.Dir(m.healStatePath), 0o700); err != nil {
		log.Printf("[WARNING] Could not create the heal state directory: %v\n", err)
		return
	}
	if err := os.WriteFile(m.healStatePath, []byte(m.now().UTC().Format(time.RFC3339)+" "+user+"\n"), 0o600); err != nil {
		log.Printf("[WARNING] Could not record the recreation of %s: %v\n", user, err)
	}
}

func (m *MacOSManager) healCooldownError(user string) error {
	last, ok := m.lastHeal(user)
	if !ok {
		return nil
	}
	age := m.now().Sub(last)
	if age >= healCooldown {
		return nil
	}
	if os.Getenv(healOverrideEnv) != "" {
		log.Printf("[WARNING] %s was recreated %s ago; %s is set, recreating again as requested.\n", user, age.Round(time.Minute), healOverrideEnv)
		return nil
	}
	return fmt.Errorf("%w %s was already recreated on %s (%s ago): recreating it again would only repeat the loop — refusing. Investigate why the account keeps failing; set %s=1 for a manual run once the cause is fixed", ErrConflict, user, last.Local().Format("2006-01-02 15:04"), age.Round(time.Minute), healOverrideEnv)
}

func (m *MacOSManager) inAdminGroup(ctx context.Context, user string) bool {
	_, err := m.run.Run(ctx, "", toolDseditgroup, "-o", "checkmember", "-m", user, "admin")
	return err == nil
}

// CleanupLegacyAdmin deletes laps-bridge via sysadminctl once targetUser holds a Secure Token (or if the bridge has no token).
func (m *MacOSManager) CleanupLegacyAdmin(ctx context.Context, targetUser string) bool {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	log.Printf("[INFO] Checking if legacy '%s' account needs to be removed...\n", LegacyBridgeAdmin)
	exists, err := m.userAccountExists(ctx, LegacyBridgeAdmin)
	if err != nil {
		log.Printf("[WARNING] Could not check for %s: %v\n", LegacyBridgeAdmin, err)
		return false
	}
	if !exists {
		log.Printf("[INFO] Legacy '%s' account is not present. System is clean.\n", LegacyBridgeAdmin)
		return true
	}
	targetThere, err := m.userAccountExists(ctx, targetUser)
	if err != nil || !targetThere {
		log.Printf("[INFO] Target admin '%s' does not exist yet. Keeping '%s' as a fallback.\n", targetUser, LegacyBridgeAdmin)
		return false
	}
	hasToken, err := m.secureTokenState(ctx, targetUser)
	if err != nil || !hasToken {
		// A token-less bridge cannot unlock FileVault, so delete it once targetUser is an admin again.
		bridgeToken, tokenErr := m.secureTokenState(ctx, LegacyBridgeAdmin)
		if m.isBridgeAccount(ctx) && tokenErr == nil && !bridgeToken && m.inAdminGroup(ctx, targetUser) {
			log.Printf("[INFO] '%s' is a token-less LAPS bridge and '%s' is an admin again. Removing the bridge; a bridge without a token is no recovery path.\n", LegacyBridgeAdmin, targetUser)
			return m.deleteLegacyAdmin(ctx)
		}
		log.Printf("[INFO] Target admin '%s' does not have a Secure Token yet. Keeping '%s' as a fallback for crypto-recovery.\n", targetUser, LegacyBridgeAdmin)
		return false
	}
	log.Printf("[WARNING] Legacy '%s' account found. Target admin '%s' is fully functional with Secure Token.\n", LegacyBridgeAdmin, targetUser)
	log.Printf("[SECURITY] Deleting '%s' account to reduce attack surface...\n", LegacyBridgeAdmin)
	return m.deleteLegacyAdmin(ctx)
}

func (m *MacOSManager) deleteLegacyAdmin(ctx context.Context) bool {
	if out, err := m.run.Run(ctx, "", toolSysadminctl, "-deleteUser", LegacyBridgeAdmin); err != nil {
		log.Printf("[WARNING] sysadminctl -deleteUser %s failed: %v | output: %s\n", LegacyBridgeAdmin, err, strings.TrimSpace(string(out)))
	}
	// Fail closed if the post-delete check fails so the vault keeps the bridge password while the account may still exist.
	if still, err := m.userAccountExists(ctx, LegacyBridgeAdmin); err != nil || still {
		log.Printf("[WARNING] sysadminctl could not delete '%s' this run, or the check failed (last-admin guard or opendirectoryd hiccup, check err: %v). Leaving it for the next check-in — never force-delete it via dscl.\n", LegacyBridgeAdmin, err)
		return false
	}
	log.Printf("[SUCCESS] '%s' account successfully removed from the system.\n", LegacyBridgeAdmin)
	return true
}
