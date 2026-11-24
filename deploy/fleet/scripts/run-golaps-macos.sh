#!/bin/bash
# Copyright 2026 Aleksandr Mikheenko
# SPDX-License-Identifier: MIT

# Fleet MDM trigger script for GoLAPS on macOS (runs as root).
# Fleet substitutes FLEET_SECRET_* values on the server before execution.
# Set FLEET_SECRET_GOLAPS_LEGACY_PASS to an empty string when not migrating a legacy admin.
set -uo pipefail
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

LAPS_BINARY="/usr/local/bin/golaps"

# Read Fleet-substituted secrets with single-quoted heredocs to prevent shell expansion.
LAPS_VAULT_TOKEN=$(cat <<'__GOLAPS_TOKEN_EOF__'
$FLEET_SECRET_GOLAPS_VAULT_TOKEN
__GOLAPS_TOKEN_EOF__
)

LEGACY_ADMIN_PASS=$(cat <<'__GOLAPS_LEGACY_EOF__'
$FLEET_SECRET_GOLAPS_LEGACY_PASS
__GOLAPS_LEGACY_EOF__
)

cleanup() {
    unset LAPS_VAULT_TOKEN
    unset LEGACY_ADMIN_PASS
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Verify that the binary and every parent directory are root-owned and not group/other writable.
verify_trusted_binary() {
    local target="$1"
    if [ -L "$target" ] || [ ! -f "$target" ]; then
        echo "[ERROR] $target is missing or a symbolic link."
        return 1
    fi
    local p="$target"
    while :; do
        if [ -L "$p" ]; then
            echo "[ERROR] Untrusted path: $p is a symbolic link."
            return 1
        fi
        local uid mode
        uid=$(stat -f '%u' "$p" 2>/dev/null) || return 1
        mode=$(stat -f '%Lp' "$p" 2>/dev/null) || return 1
        if [ "$uid" != "0" ]; then
            echo "[ERROR] Untrusted path: $p is owned by uid $uid, not root."
            return 1
        fi
        if (( (8#$mode & 022) != 0 )); then
            echo "[ERROR] Untrusted path: $p is writable by group or other (mode $mode)."
            return 1
        fi
        [ "$p" = "/" ] && break
        p=$(dirname "$p")
    done
    return 0
}

# Abort if the Fleet secret was not substituted or is empty.
# Split the literal marker so Fleet does not substitute inside the check.
if [ -z "$LAPS_VAULT_TOKEN" ] || [ "$LAPS_VAULT_TOKEN" = '$''FLEET_SECRET_GOLAPS_VAULT_TOKEN' ]; then
    echo "[ERROR] FLEET_SECRET_GOLAPS_VAULT_TOKEN is empty or not configured."
    exit 1
fi

if [ "$LEGACY_ADMIN_PASS" = '$''FLEET_SECRET_GOLAPS_LEGACY_PASS' ]; then
    LEGACY_ADMIN_PASS=""
fi

# Skip rotation on very low battery to avoid state desync during sudden shutdown.
BATT_INFO=$(pmset -g batt 2>/dev/null || true)
if grep -qi "Battery Power" <<< "$BATT_INFO" || grep -qi "Discharging" <<< "$BATT_INFO"; then
    BATT_PCT=$(echo "$BATT_INFO" | grep -oE '[0-9]+%' | tr -d '%' | head -n 1)
    if [[ -n "$BATT_PCT" && "$BATT_PCT" -lt 10 ]]; then
        echo "[WARNING] Battery is below 10% ($BATT_PCT%). Skipping rotation."
        exit 0
    fi
fi

# Confirm binary integrity before running GoLAPS as root.
if ! verify_trusted_binary "$LAPS_BINARY"; then
    echo "[ERROR] Refusing to run untrusted binary $LAPS_BINARY."
    exit 1
fi

echo "[INFO] Starting GoLAPS rotation..."

# Pass secrets over stdin and prevent system sleep during vault calls.
printf '%s\n%s\n' "$LAPS_VAULT_TOKEN" "$LEGACY_ADMIN_PASS" | /usr/bin/caffeinate -i "$LAPS_BINARY" --secrets-from-stdin
EXIT_CODE=$?

if [ "$EXIT_CODE" -eq 75 ]; then
    echo "[INFO] GoLAPS skipped rotation (exit 75)."
    exit 0
fi

if [ "$EXIT_CODE" -ne 0 ]; then
    echo "[ERROR] GoLAPS failed with exit code $EXIT_CODE."
    exit "$EXIT_CODE"
fi

echo "[SUCCESS] GoLAPS rotation completed."
exit 0
