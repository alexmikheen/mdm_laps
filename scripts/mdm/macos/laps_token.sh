#!/bin/bash
# ==============================================================================
# Script Name: laps_token.sh
# Description: Injects the vault token, runs pre-rotation account repair, and executes the GoLAPS updater.
# Note for MDM: Replace the placeholder values in the VARIABLES section before deployment.
# Logs place: MDM logs / stdout + /Library/Logs/golaps.log (tail-capped; written by this script and by golaps itself).
#             Most MDMs keep only the latest run per device, so the local file is the only run history that survives.
# Required Permissions: root
# Safety Notes: Uses caffeinate to prevent sleep during API calls. Battery check prevents state desync.
# ==============================================================================
# Strict-ish mode. Deliberately NOT `set -e`: several checks below exit 0 on purpose (PKG not downloaded yet, low battery) and a bare -e would turn every non-zero probe into an abort. What we do want is an unset variable to be a hard error rather than an empty string silently standing in for a secret, and a failing stage of a pipeline not to be masked by a later one.
set -uo pipefail

# ==============================================================================
# 1. VARIABLES (Replace placeholders with actual secrets in your MDM only)
# DO NOT COMMIT ACTUAL SECRETS TO GIT!
export LAPS_VAULT_TYPE="__VAULT_TYPE__"
export LAPS_VAULT_TOKEN="__VAULT_SERVICE_TOKEN_OPTIONAL__"
export LEGACY_ADMIN_PASS="__LEGACY_ADMIN_PASSWORD_OPTIONAL__"
# Optional: a legacy admin account from a previous MDM/LAPS deployment that this script retires once the managed admin holds a Secure Token. Leave the placeholder to skip that cleanup.
LEGACY_ADMIN_ACCOUNT="__LEGACY_ADMIN_ACCOUNT_OPTIONAL__"
# Optional: a URL whose reachability proves the vault API is reachable (the Wasm SDK panics on a dead network). Leave the placeholder to use the provider default, set empty to skip the probe.
REACHABILITY_URL="__REACHABILITY_URL_OPTIONAL__"

KEYCHAIN="/Library/Keychains/System.keychain"
KEYCHAIN_LABEL="GoLAPS_Vault_Token"
LAPS_BINARY="/usr/local/bin/golaps"
MANAGED_PREFS_DOMAIN="io.github.golaps"
BRIDGE_ADMIN="laps-bridge"
LOG_FILE="/Library/Logs/golaps.log"

mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
# Probe writability once rather than redirecting blindly, so a non-root manual run does not spray "permission denied" into the MDM log.
LOG_OK=0
if : >> "$LOG_FILE" 2>/dev/null; then
    LOG_OK=1
    # The log names local accounts, so keep it root-only-writable.
    chown root:wheel "$LOG_FILE" 2>/dev/null || true
    chmod 640 "$LOG_FILE" 2>/dev/null || true
fi
# Tail-cap so the file cannot grow without bound (golaps caps the same file on its side).
if [ "$LOG_OK" -eq 1 ] && [ -f "$LOG_FILE" ]; then
    { tail -n 2000 "$LOG_FILE" > "${LOG_FILE}.tmp" && mv "${LOG_FILE}.tmp" "$LOG_FILE"; } 2>/dev/null || true
fi

log() {
    local m="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "$m"
    if [ "$LOG_OK" -eq 1 ]; then
        echo "$m" >> "$LOG_FILE" 2>/dev/null || true
    fi
}

# --- GUARANTEED CLEANUP ---
cleanup() {
    log "[INFO] Removing token from System Keychain and clearing variables..."
    security delete-generic-password -l "$KEYCHAIN_LABEL" "$KEYCHAIN" >/dev/null 2>&1
    unset LEGACY_ADMIN_PASS
    unset LAPS_VAULT_TOKEN
    unset OP_SERVICE_ACCOUNT_TOKEN
    unset VAULT_TOKEN
}
trap cleanup EXIT INT TERM

# --- 2. PRE-FLIGHT CHECKS (Fail-safes) ---
if [ "$LAPS_VAULT_TYPE" == "__VAULT_TYPE__" ] || [ -z "$LAPS_VAULT_TYPE" ]; then
    log "[ERROR] Vault type is not configured. Please replace __VAULT_TYPE__ with onepassword, hashicorp, bitwarden, aws, or azure."
    exit 1
fi

if [ "$LAPS_VAULT_TOKEN" == "__VAULT_SERVICE_TOKEN_OPTIONAL__" ]; then
    unset LAPS_VAULT_TOKEN
fi

if [ "$LEGACY_ADMIN_PASS" == "__LEGACY_ADMIN_PASSWORD_OPTIONAL__" ]; then
    unset LEGACY_ADMIN_PASS
fi

if [ "$LEGACY_ADMIN_ACCOUNT" == "__LEGACY_ADMIN_ACCOUNT_OPTIONAL__" ]; then
    LEGACY_ADMIN_ACCOUNT=""
fi

if [ "$REACHABILITY_URL" == "__REACHABILITY_URL_OPTIONAL__" ]; then
    case "$LAPS_VAULT_TYPE" in
        onepassword|1password) REACHABILITY_URL="https://my.1password.com" ;;
        *) REACHABILITY_URL="" ;;
    esac
fi

if [ -n "${LAPS_VAULT_TOKEN:-}" ]; then
    case "$LAPS_VAULT_TYPE" in
        onepassword|1password)
            export OP_SERVICE_ACCOUNT_TOKEN="$LAPS_VAULT_TOKEN"
            ;;
        hashicorp)
            export VAULT_TOKEN="$LAPS_VAULT_TOKEN"
            ;;
    esac
fi

if [ ! -f "$LAPS_BINARY" ]; then
    log "[INFO] LAPS binary not found at $LAPS_BINARY."
    log "[INFO] The PKG is likely still installing. Exiting gracefully to wait for the next MDM check-in."
    exit 0
fi

# --- TARGET ADMIN RESOLUTION (used by diagnostics, counter hygiene and legacy cleanup) ---
TARGET_ADMIN="${LAPS_ADMIN_USER:-}"
if [ -z "$TARGET_ADMIN" ]; then
    TARGET_ADMIN=$(defaults read "/Library/Managed Preferences/$MANAGED_PREFS_DOMAIN" AdminUser 2>/dev/null || true)
fi
if [ -z "$TARGET_ADMIN" ]; then
    log "[INFO] No AdminUser configured (LAPS_ADMIN_USER or the $MANAGED_PREFS_DOMAIN profile) — skipping the pre-rotation repair; the binary reports the missing config itself."
fi

# --- 2.5 SERVICE-ACCOUNT AUTH GATE + REPAIR ---
# Clears the failed-login counter, asks OD for the auth verdict, repairs the known change-required blockers, and GATES the rotation on the result: a still-blocked account would only feed the phantom administrative reset and commit one more wrong password to the vault.
if [ -n "$TARGET_ADMIN" ] && id "$TARGET_ADMIN" >/dev/null 2>&1; then
    FAILED_COUNT=$(dscl . -read "/Users/$TARGET_ADMIN" accountPolicyData 2>/dev/null | grep -A1 failedLoginCount | grep -oE '[0-9]+' | head -n 1)
    if [ -n "$FAILED_COUNT" ] && [ "$FAILED_COUNT" -gt 0 ]; then
        # A recurring non-zero count is the fleet-wide desync detector: the vault password is wrong on this device.
        log "[WARNING] $TARGET_ADMIN has $FAILED_COUNT recorded failed login attempt(s) — clearing."
    fi
    dscl . -deletepl "/Users/$TARGET_ADMIN" accountPolicyData failedLoginCount 2>/dev/null || true
    dscl . -deletepl "/Users/$TARGET_ADMIN" accountPolicyData failedLoginTimestamp 2>/dev/null || true

    # Re-assert admin membership every run: privilege-management tools (e.g. Admin By Request) demote admins that are not in their exclusion list, and a demoted service admin rotates green while being useless for recovery.
    if ! dseditgroup -o checkmember -m "$TARGET_ADMIN" admin >/dev/null 2>&1; then
        log "[WARNING] $TARGET_ADMIN is not in the admin group (privilege-management cleanup?) — re-adding. Recurring on this device means $TARGET_ADMIN must go into the tool's exclusion list (e.g. AbR ExcludedAccounts)."
        dseditgroup -o edit -a "$TARGET_ADMIN" -t user admin 2>/dev/null || log "[ERROR] Could not re-add $TARGET_ADMIN to the admin group."
    fi

    VERDICT=$(pwpolicy -u "$TARGET_ADMIN" authentication-allowed 2>&1 | tr '\n' ' ')
    log "[INFO] pwpolicy verdict for $TARGET_ADMIN: $VERDICT"

    if [[ "$VERDICT" == *"until password is changed"* ]]; then
        # Evidence BEFORE repair — the source of the change-requirement must survive in this log.
        log "[REPAIR] legacy per-user policy: $(pwpolicy -u "$TARGET_ADMIN" -getpolicy 2>&1 | tail -n +2 | tr '\n' ' ' | cut -c1-300)"
        log "[REPAIR] PasswordPolicyOptions: $(dscl . -read "/Users/$TARGET_ADMIN" PasswordPolicyOptions 2>&1 | tr '\n' ' ' | cut -c1-300)"
        # GLOBAL account policies — the layer the per-user repair below cannot reach; the policyIdentifier here names the real blocker.
        log "[REPAIR] GLOBAL account policies: $(pwpolicy -getaccountpolicies 2>&1 | tail -n +2 | tr '\n' ' ' | cut -c1-900)"
        log "[REPAIR] accountPolicyData (full): $(dscl . -read "/Users/$TARGET_ADMIN" accountPolicyData 2>&1 | tr '\n' ' ' | cut -c1-800)"
        log "[REPAIR] AuthenticationAuthority: $(dscl . -read "/Users/$TARGET_ADMIN" AuthenticationAuthority 2>&1 | tr '\n' ' ' | cut -c1-300)"
        PW_SET_EPOCH=$(dscl . -read "/Users/$TARGET_ADMIN" accountPolicyData 2>/dev/null | grep -A1 passwordLastSetTime | grep -oE '[0-9]+' | head -n 1)
        [ -n "$PW_SET_EPOCH" ] && log "[REPAIR] passwordLastSetTime: $(date -r "$PW_SET_EPOCH" '+%Y-%m-%d %H:%M:%S')"

        # Step 1: clear the legacy change-required flags. Service account only — human accounts are never touched. Output is logged: a silent failure here previously looked identical to "the fix did not work".
        log "[REPAIR] setpolicy output: $(pwpolicy -u "$TARGET_ADMIN" -setpolicy "newPasswordRequired=0 maxMinutesUntilChangePassword=0" 2>&1 | tr '\n' ' ' | cut -c1-200)"
        VERDICT=$(pwpolicy -u "$TARGET_ADMIN" authentication-allowed 2>&1 | tr '\n' ' ')
        log "[REPAIR] verdict after legacy-policy reset: $VERDICT"

        # Step 2 (escalation): drop per-user account policies. Global/profile policies are NOT touched by design.
        if [[ "$VERDICT" == *"not"*"allowed"* ]]; then
            log "[REPAIR] clearaccountpolicies output: $(pwpolicy -u "$TARGET_ADMIN" -clearaccountpolicies 2>&1 | tr '\n' ' ' | cut -c1-200)"
            VERDICT=$(pwpolicy -u "$TARGET_ADMIN" authentication-allowed 2>&1 | tr '\n' ' ')
            log "[REPAIR] verdict after clearing per-user account policies: $VERDICT"
        fi
    fi

    if [[ "$VERDICT" == *"not"*"allowed"* ]]; then
        # Ask the binary what it can do instead of comparing version numbers: a hardcoded version gate is wrong exactly once, and that once hands devices over to a binary that can only phantom-reset and poison the vault. A binary without the flag prints nothing / exits non-zero, which reads as "cannot" — the safe direction.
        CAPS=$("$LAPS_BINARY" --capabilities 2>/dev/null || true)
        if [[ "$CAPS" == *"recreate-locked"* ]]; then
            log "[WARNING] $TARGET_ADMIN is still blocked after every soft repair — handing over to golaps for account recreation (capabilities: $CAPS). The console user may get a GUI token prompt."
        else
            log "[ERROR] $TARGET_ADMIN still cannot authenticate after repair, and the installed binary cannot recreate locked accounts (capabilities: ${CAPS:-none}). Skipping rotation: it could only produce a phantom reset and another wrong vault password."
            exit 1
        fi
    fi
fi

# --- BATTERY CHECK ---
BATT_INFO=$(pmset -g batt)
if grep -q "Battery Power" <<< "$BATT_INFO" || grep -q "Discharging" <<< "$BATT_INFO"; then
    BATT_PCT=$(echo "$BATT_INFO" | grep -oE '[0-9]+%' | tr -d '%' | head -n 1)
    if [[ -n "$BATT_PCT" && "$BATT_PCT" -lt 10 ]]; then
        log "[WARNING] Laptop is on battery power and below 10% ($BATT_PCT%)."
        log "[INFO] Aborting LAPS rotation to prevent state desync in case of sudden shutdown."
        exit 0
    fi
fi

# --- NETWORK CONNECTIVITY CHECK ---
if [ -n "$REACHABILITY_URL" ]; then
    log "[INFO] Checking connection to the vault API..."
    if ! curl -s -m 10 "$REACHABILITY_URL" > /dev/null; then
        log "[ERROR] Network timeout or no internet connection to the vault API."
        log "[INFO] Exiting early to prevent Wasm SDK panics. Will retry on next MDM check-in."
        exit 1
    fi
fi

# --- 3. TOKEN HAND-OFF ---
# Environment only: the binary reads env FIRST and runs as a direct child, so a keychain copy is redundant — and `security add-generic-password -w "$TOKEN"` puts the secret in argv (world-readable via ps) with no stdin alternative when a keychain path is given. The binary's keychain READ fallback stays for manually pre-provisioned items; cleanup and the startup shred keep deleting leftovers.
if [ -n "${LAPS_VAULT_TOKEN:-}" ]; then
    log "[INFO] Handing the vault token to golaps via the environment (no keychain copy)."
    security delete-generic-password -l "$KEYCHAIN_LABEL" "$KEYCHAIN" >/dev/null 2>&1
else
    log "[INFO] Vault token not provided in this script. The binary will use provider-specific environment/configuration."
fi

# --- 4. EXECUTE THE LAPS UPDATER (WITH CAFFEINATE) ---
log "[INFO] Starting LAPS rotation process..."

# caffeinate -i prevents system sleep ensuring the vault network call completes safely
/usr/bin/caffeinate -i "$LAPS_BINARY"
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    # golaps also exits non-zero when the rotation succeeded but the target admin still holds no Secure Token — the device has no FileVault recovery account and this run must show up red in the MDM console, not as Pass.
    log "[ERROR] LAPS binary failed with exit code $EXIT_CODE."
    log "[INFO] Keeping any legacy/bridge admin as crypto-recovery fallback; skipping cleanup."
    exit 1
fi

log "[SUCCESS] LAPS rotation completed successfully."

# --- 5. POST-ROTATION SECURITY CLEANUP (LEGACY/BRIDGE ADMIN) ---
# Retires the configured legacy admin (from a previous deployment) and the temporary bridge admin that golaps creates to satisfy macOS's last-admin guard — but only once the managed admin is fully functional WITH a Secure Token, because until then they are the only crypto-recovery path.
retire_account() {
    local account="$1"
    if [ -z "$account" ] || ! id "$account" &>/dev/null; then
        return 0
    fi
    if [ -z "$TARGET_ADMIN" ] || ! id "$TARGET_ADMIN" &>/dev/null; then
        log "[INFO] Target admin does not exist yet. Keeping '$account' as a fallback."
        return 0
    fi
    TOKEN_STATUS=$(sysadminctl -secureTokenStatus "$TARGET_ADMIN" 2>&1)
    # Match the whole phrase: a bare "ENABLED" test is one typo from matching "DISABLED", which would delete the only crypto-recovery account we still have.
    if [[ "$TOKEN_STATUS" == *"is ENABLED"* ]] || [[ "$TOKEN_STATUS" == *"is ON"* ]]; then
        log "[WARNING] Account '$account' found. Target admin '$TARGET_ADMIN' is fully functional with Secure Token."
        log "[SECURITY] Deleting '$account' to reduce attack surface..."
        # sysadminctl ONLY — a raw `dscl . -delete` bypasses the last-admin guard and orphans the SEP identity, leaving a tombstone that makes every later `sysadminctl -addUser` for the same name exit 0 without creating anything; the binary reuses the bridge name during heals. Delete the supported way, verify, and leave a survivor for the next run.
        sysadminctl -deleteUser "$account" >/dev/null 2>&1
        if id "$account" &>/dev/null; then
            log "[WARNING] sysadminctl could not delete '$account' this run (last-admin guard or opendirectoryd hiccup). Leaving it for the next check-in — do NOT force-delete via dscl."
        else
            log "[SUCCESS] '$account' successfully removed from the system."
        fi
    else
        log "[INFO] Target admin '$TARGET_ADMIN' does not have a Secure Token yet. Keeping '$account' as a fallback for crypto-recovery."
    fi
}

retire_account "$BRIDGE_ADMIN"
retire_account "$LEGACY_ADMIN_ACCOUNT"

exit 0
