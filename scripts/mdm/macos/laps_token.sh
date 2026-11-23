#!/bin/bash
# Copyright 2026 Aleksandr Mikheenko
# SPDX-License-Identifier: MIT

# MDM trigger script for GoLAPS on macOS (run as root).
# Use -u and pipefail, not -e, because preflight checks exit 0 on skip conditions.
set -uo pipefail
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

# Replace placeholders with real secrets in your MDM only; never commit secrets to Git.
export LAPS_VAULT_TYPE="__VAULT_TYPE__"
LAPS_VAULT_TOKEN="__VAULT_SERVICE_TOKEN_OPTIONAL__"
LEGACY_ADMIN_PASS="__LEGACY_ADMIN_PASSWORD_OPTIONAL__"
# Optional legacy admin to delete after the managed admin holds a Secure Token.
LEGACY_ADMIN_ACCOUNT="__LEGACY_ADMIN_ACCOUNT_OPTIONAL__"
# Optional vault reachability probe URL; leave empty to skip.
REACHABILITY_URL="__REACHABILITY_URL_OPTIONAL__"

KEYCHAIN="/Library/Keychains/System.keychain"
KEYCHAIN_LABEL="GoLAPS_Vault_Token"
LAPS_BINARY="/usr/local/bin/golaps"
MANAGED_PREFS_DOMAIN="io.github.golaps"
BRIDGE_ADMIN="laps-bridge"
LOG_FILE="/Library/Logs/golaps.log"

mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
# Probe log writability once so non-root runs do not spam permission errors.
LOG_OK=0
if [ ! -L "$LOG_FILE" ] && : >> "$LOG_FILE" 2>/dev/null; then
    LOG_OK=1
    # Keep the log readable and writable by root only.
    chown root:wheel "$LOG_FILE" 2>/dev/null || true
    chmod 600 "$LOG_FILE" 2>/dev/null || true
fi
# Cap the log under umask 077 so rotation never creates a world-readable file.
if [ "$LOG_OK" -eq 1 ] && [ -f "$LOG_FILE" ] && [ ! -L "$LOG_FILE" ]; then
    (
        umask 077
        tmp_log=$(mktemp "${LOG_FILE}.XXXXXX") || exit 1
        tail -n 2000 "$LOG_FILE" > "$tmp_log" && chown root:wheel "$tmp_log" 2>/dev/null && chmod 600 "$tmp_log" && mv "$tmp_log" "$LOG_FILE" || rm -f "$tmp_log"
    ) 2>/dev/null || true
fi

log() {
    local m="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "$m"
    if [ "$LOG_OK" -eq 1 ]; then
        echo "$m" >> "$LOG_FILE" 2>/dev/null || true
    fi
}

cleanup() {
    log "[INFO] Removing token from System Keychain and clearing variables..."
    security delete-generic-password -l "$KEYCHAIN_LABEL" "$KEYCHAIN" >/dev/null 2>&1
    unset LEGACY_ADMIN_PASS
    unset LAPS_VAULT_TOKEN
    unset OP_SERVICE_ACCOUNT_TOKEN
    unset VAULT_TOKEN
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

verify_trusted_binary() {
    local target="$1"
    if [ -L "$target" ] || [ ! -f "$target" ]; then
        log "[ERROR] $target is missing or a symbolic link."
        return 1
    fi
    local p="$target"
    while :; do
        if [ -L "$p" ]; then
            log "[ERROR] Untrusted path: $p is a symbolic link."
            return 1
        fi
        local uid mode
        uid=$(stat -f '%u' "$p" 2>/dev/null) || return 1
        mode=$(stat -f '%Lp' "$p" 2>/dev/null) || return 1
        if [ "$uid" != "0" ]; then
            log "[ERROR] Untrusted path: $p is owned by uid $uid, not root."
            return 1
        fi
        if (( (8#$mode & 022) != 0 )); then
            log "[ERROR] Untrusted path: $p is writable by group or other (mode $mode)."
            return 1
        fi
        [ "$p" = "/" ] && break
        p=$(dirname "$p")
    done
    return 0
}

if [ "$LAPS_VAULT_TYPE" == "__VAULT_TYPE__" ] || [ -z "$LAPS_VAULT_TYPE" ]; then
    log "[ERROR] Vault type is not configured. Please replace __VAULT_TYPE__ with onepassword, hashicorp, bitwarden, aws, or azure."
    exit 1
fi

if [ "$LAPS_VAULT_TOKEN" == "__VAULT_SERVICE_TOKEN_OPTIONAL__" ]; then
    LAPS_VAULT_TOKEN=""
fi

if [ "$LEGACY_ADMIN_PASS" == "__LEGACY_ADMIN_PASSWORD_OPTIONAL__" ]; then
    LEGACY_ADMIN_PASS=""
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

# Keep secrets out of exported env vars; pass them over stdin below.

if [ ! -f "$LAPS_BINARY" ]; then
    log "[INFO] LAPS binary not found at $LAPS_BINARY."
    log "[INFO] The PKG is likely still installing. Exiting gracefully to wait for the next MDM check-in."
    exit 0
fi

# Verify binary ownership and permissions before executing golaps as root (including --capabilities).
if ! verify_trusted_binary "$LAPS_BINARY"; then
    log "[ERROR] Refusing to execute untrusted binary $LAPS_BINARY."
    exit 1
fi

TARGET_ADMIN="${LAPS_ADMIN_USER:-}"
if [ -z "$TARGET_ADMIN" ]; then
    TARGET_ADMIN=$(defaults read "/Library/Managed Preferences/$MANAGED_PREFS_DOMAIN" AdminUser 2>/dev/null || true)
fi
if [ -z "$TARGET_ADMIN" ]; then
    log "[INFO] No AdminUser configured (LAPS_ADMIN_USER or the $MANAGED_PREFS_DOMAIN profile) — skipping the pre-rotation repair; the binary reports the missing config itself."
fi

# Check failed-login count, restore admin membership, and clear per-user password blocks.
if [ -n "$TARGET_ADMIN" ] && id "$TARGET_ADMIN" >/dev/null 2>&1; then
    FAILED_COUNT=$(dscl . -read "/Users/$TARGET_ADMIN" accountPolicyData 2>/dev/null | grep -A1 failedLoginCount | grep -oE '[0-9]+' | head -n 1)
    if [ -n "$FAILED_COUNT" ] && [ "$FAILED_COUNT" -gt 0 ]; then
        log "[WARNING] $TARGET_ADMIN has $FAILED_COUNT recorded failed login attempt(s) — clearing."
    fi
    dscl . -deletepl "/Users/$TARGET_ADMIN" accountPolicyData failedLoginCount 2>/dev/null || true
    dscl . -deletepl "/Users/$TARGET_ADMIN" accountPolicyData failedLoginTimestamp 2>/dev/null || true

    # Restore admin membership if a privilege-management tool demoted the account.
    if ! dseditgroup -o checkmember -m "$TARGET_ADMIN" admin >/dev/null 2>&1; then
        log "[WARNING] $TARGET_ADMIN is not in the admin group (privilege-management cleanup?) — re-adding. Recurring on this device means $TARGET_ADMIN must go into the tool's exclusion list (e.g. AbR ExcludedAccounts)."
        dseditgroup -o edit -a "$TARGET_ADMIN" -t user admin 2>/dev/null || log "[ERROR] Could not re-add $TARGET_ADMIN to the admin group."
    fi

    VERDICT=$(pwpolicy -u "$TARGET_ADMIN" authentication-allowed 2>&1 | tr '\n' ' ')
    log "[INFO] pwpolicy verdict for $TARGET_ADMIN: $VERDICT"

    if [[ "$VERDICT" == *"until password is changed"* ]]; then
        log "[REPAIR] legacy per-user policy: $(pwpolicy -u "$TARGET_ADMIN" -getpolicy 2>&1 | tail -n +2 | tr '\n' ' ' | cut -c1-300)"
        log "[REPAIR] PasswordPolicyOptions: $(dscl . -read "/Users/$TARGET_ADMIN" PasswordPolicyOptions 2>&1 | tr '\n' ' ' | cut -c1-300)"
        log "[REPAIR] GLOBAL account policies: $(pwpolicy -getaccountpolicies 2>&1 | tail -n +2 | tr '\n' ' ' | cut -c1-900)"
        log "[REPAIR] accountPolicyData (full): $(dscl . -read "/Users/$TARGET_ADMIN" accountPolicyData 2>&1 | tr '\n' ' ' | cut -c1-800)"
        log "[REPAIR] AuthenticationAuthority: $(dscl . -read "/Users/$TARGET_ADMIN" AuthenticationAuthority 2>&1 | tr '\n' ' ' | cut -c1-300)"
        PW_SET_EPOCH=$(dscl . -read "/Users/$TARGET_ADMIN" accountPolicyData 2>/dev/null | grep -A1 passwordLastSetTime | grep -oE '[0-9]+' | head -n 1)
        [ -n "$PW_SET_EPOCH" ] && log "[REPAIR] passwordLastSetTime: $(date -r "$PW_SET_EPOCH" '+%Y-%m-%d %H:%M:%S')"

        # Clear per-user change-required flags only; do not alter global policies.
        log "[REPAIR] setpolicy output: $(pwpolicy -u "$TARGET_ADMIN" -setpolicy "newPasswordRequired=0 maxMinutesUntilChangePassword=0" 2>&1 | tr '\n' ' ' | cut -c1-200)"
        VERDICT=$(pwpolicy -u "$TARGET_ADMIN" authentication-allowed 2>&1 | tr '\n' ' ')
        log "[REPAIR] verdict after legacy-policy reset: $VERDICT"

        # Escalate to per-user policy clear if still blocked.
        if [[ "$VERDICT" == *"not"*"allowed"* ]]; then
            log "[REPAIR] clearaccountpolicies output: $(pwpolicy -u "$TARGET_ADMIN" -clearaccountpolicies 2>&1 | tr '\n' ' ' | cut -c1-200)"
            VERDICT=$(pwpolicy -u "$TARGET_ADMIN" authentication-allowed 2>&1 | tr '\n' ' ')
            log "[REPAIR] verdict after clearing per-user account policies: $VERDICT"
        fi
    fi

    if [[ "$VERDICT" == *"not"*"allowed"* ]]; then
        # Check binary capabilities instead of version numbers so older binaries fail safe.
        CAPS=$("$LAPS_BINARY" --capabilities 2>/dev/null || true)
        if [[ "$CAPS" == *"recreate-locked"* ]]; then
            log "[WARNING] $TARGET_ADMIN is still blocked after every soft repair — handing over to golaps for account recreation (capabilities: $CAPS). The console user may get a GUI token prompt."
        else
            log "[ERROR] $TARGET_ADMIN still cannot authenticate after repair, and the installed binary cannot recreate locked accounts (capabilities: ${CAPS:-none}). Skipping rotation: it could only produce a phantom reset and another wrong vault password."
            exit 1
        fi
    fi
fi

BATT_INFO=$(pmset -g batt)
if grep -q "Battery Power" <<< "$BATT_INFO" || grep -q "Discharging" <<< "$BATT_INFO"; then
    BATT_PCT=$(echo "$BATT_INFO" | grep -oE '[0-9]+%' | tr -d '%' | head -n 1)
    if [[ -n "$BATT_PCT" && "$BATT_PCT" -lt 10 ]]; then
        log "[WARNING] Laptop is on battery power and below 10% ($BATT_PCT%)."
        log "[INFO] Aborting LAPS rotation to prevent state desync in case of sudden shutdown."
        exit 0
    fi
fi

if [ -n "$REACHABILITY_URL" ]; then
    log "[INFO] Checking connection to the vault API..."
    if ! curl -s -m 10 "$REACHABILITY_URL" > /dev/null; then
        log "[ERROR] Network timeout or no internet connection to the vault API."
        log "[INFO] Exiting early to prevent Wasm SDK panics. Will retry on next MDM check-in."
        exit 1
    fi
fi

# Pass secrets via --secrets-from-stdin so they never appear in argv, env, or Keychain.
if [ -n "${LAPS_VAULT_TOKEN:-}" ]; then
    log "[INFO] Handing the vault token to golaps via stdin (--secrets-from-stdin)."
    security delete-generic-password -l "$KEYCHAIN_LABEL" "$KEYCHAIN" >/dev/null 2>&1
else
    log "[INFO] Vault token not provided in this script. The binary will use provider-specific environment/configuration."
fi

if ! verify_trusted_binary "$LAPS_BINARY"; then
    log "[ERROR] Refusing to execute untrusted binary $LAPS_BINARY."
    exit 1
fi

log "[INFO] Starting LAPS rotation process..."

# Prevent sleep during vault network calls.
if [ -n "${LAPS_VAULT_TOKEN:-}" ] || [ -n "${LEGACY_ADMIN_PASS:-}" ]; then
    printf '%s\n%s\n' "${LAPS_VAULT_TOKEN:-}" "${LEGACY_ADMIN_PASS:-}" | /usr/bin/caffeinate -i "$LAPS_BINARY" --secrets-from-stdin
else
    /usr/bin/caffeinate -i "$LAPS_BINARY"
fi
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    # Keep non-zero exit when Secure Token is still missing so MDM does not report Pass.
    log "[ERROR] LAPS binary failed with exit code $EXIT_CODE."
    log "[INFO] Keeping any legacy/bridge admin as crypto-recovery fallback; skipping cleanup."
    exit 1
fi

log "[SUCCESS] LAPS rotation completed successfully."

# Retire legacy and bridge admins once the managed admin holds a Secure Token.
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
    if [[ "$TOKEN_STATUS" == *"is ENABLED"* ]] || [[ "$TOKEN_STATUS" == *"is ON"* ]]; then
        log "[WARNING] Account '$account' found. Target admin '$TARGET_ADMIN' is fully functional with Secure Token."
        log "[SECURITY] Deleting '$account' to reduce attack surface..."
            # Never fall back to dscl -delete; it bypasses the last-admin guard.
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
