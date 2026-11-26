#!/bin/bash
# Copyright 2026 Aleksandr Mikheenko
# SPDX-License-Identifier: MIT

# MDM trigger script for GoLAPS on macOS (run as root).
# Use -u and pipefail, not -e, because preflight checks exit 0 on skip conditions.
set -uo pipefail
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

# Replace placeholders with real secrets in your MDM only. Never commit secrets to Git.
# Never export secret variables at assignment so child processes do not inherit them.
export LAPS_VAULT_TYPE="__VAULT_TYPE__"
LAPS_VAULT_TOKEN=$(cat <<'__GOLAPS_TOKEN_EOF__'
__VAULT_SERVICE_TOKEN_OPTIONAL__
__GOLAPS_TOKEN_EOF__
)
LEGACY_ADMIN_PASS=$(cat <<'__GOLAPS_LEGACY_EOF__'
__LEGACY_ADMIN_PASSWORD_OPTIONAL__
__GOLAPS_LEGACY_EOF__
)

LAPS_BINARY="/usr/local/bin/golaps"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

cleanup() {
    unset LEGACY_ADMIN_PASS LAPS_VAULT_TOKEN OP_SERVICE_ACCOUNT_TOKEN VAULT_TOKEN
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Keep this check in the trigger because the binary cannot check its own path before it runs.
trusted_path() {
    local p="$1" target="$1" info
    while :; do
        [ -L "$p" ] && { log "[ERROR] $p is a symbolic link."; return 1; }
        info=$(/usr/bin/stat -f '%u %Lp' "$p" 2>/dev/null) || { log "[ERROR] $p cannot be checked."; return 1; }
        [ "${info%% *}" == "0" ] || { log "[ERROR] $p is owned by uid ${info%% *}, not by root."; return 1; }
        (( (8#${info##* } & 8#022) == 0 )) || { log "[ERROR] $p is writable by group or other (mode ${info##* })."; return 1; }
        [ "$p" == "/" ] && break
        p=$(/usr/bin/dirname "$p")
    done
    [ -f "$target" ] || { log "[ERROR] $target is not a regular file."; return 1; }
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

if [[ "$LAPS_VAULT_TOKEN" == *$'\n'* ]] || [[ "$LAPS_VAULT_TOKEN" == *$'\r'* ]] || [[ "$LEGACY_ADMIN_PASS" == *$'\n'* ]] || [[ "$LEGACY_ADMIN_PASS" == *$'\r'* ]]; then
    log "[ERROR] Secrets must not contain line breaks."
    exit 1
fi

if [ ! -f "$LAPS_BINARY" ] || [ ! -x "$LAPS_BINARY" ]; then
    log "[INFO] LAPS binary not found at $LAPS_BINARY."
    log "[INFO] The PKG is likely still installing. Exiting gracefully to wait for the next MDM check-in."
    exit 0
fi

if ! trusted_path "$LAPS_BINARY"; then
    log "[ERROR] [UNTRUSTED BINARY] $LAPS_BINARY is not safe to run as root. The secrets stay in the trigger. Correct the owner and the mode of the path above."
    exit 1
fi

CAPABILITIES=$("$LAPS_BINARY" --capabilities 2>/dev/null) || CAPABILITIES=""
if [[ " $CAPABILITIES " != *" preflight "* ]] || [[ " $CAPABILITIES " != *" secrets-stdin "* ]]; then
    log "[INFO] The installed LAPS binary does not report the preflight and secrets-stdin capabilities."
    log "[INFO] Waiting for the PKG of the current release. Exiting gracefully until the next MDM check-in."
    exit 0
fi

# Spread the daily runs because an MDM starts them at the same minute and the vault server may rate-limit the burst.
JITTER_MAX="${LAPS_JITTER_MAX_SECONDS:-900}"
if [[ "$JITTER_MAX" =~ ^[0-9]+$ ]] && [ "$JITTER_MAX" -gt 0 ]; then
    DELAY=$((RANDOM % JITTER_MAX))
    log "[INFO] Waiting ${DELAY}s before the run to spread the fleet load on the vault."
    # Keep env -i so the sleep and its caffeinate carry no variable for up to 15 minutes.
    /usr/bin/env -i /usr/bin/caffeinate -i /bin/sleep "$DELAY"
    export LAPS_STARTUP_DELAY_SECONDS="$DELAY"
fi

if ! trusted_path "$LAPS_BINARY"; then
    log "[ERROR] [UNTRUSTED BINARY] $LAPS_BINARY is not safe to run as root. The secrets stay in the trigger. Correct the owner and the mode of the path above."
    exit 1
fi

log "[INFO] Starting LAPS rotation process..."
# Pass secrets over stdin (--secrets-from-stdin) so they never appear in argv, env, or Keychain.
if [ -n "$LAPS_VAULT_TOKEN" ] || [ -n "$LEGACY_ADMIN_PASS" ]; then
    printf '%s\n%s\n' "$LAPS_VAULT_TOKEN" "$LEGACY_ADMIN_PASS" | /usr/bin/caffeinate -i "$LAPS_BINARY" --secrets-from-stdin
else
    /usr/bin/caffeinate -i "$LAPS_BINARY"
fi
EXIT_CODE=$?

if [ "$EXIT_CODE" -eq 75 ]; then
    log "[INFO] GoLAPS skipped rotation (exit 75)."
    exit 0
fi

exit "$EXIT_CODE"
