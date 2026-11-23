#!/bin/bash
# Copyright 2026 Aleksandr Mikheenko
# SPDX-License-Identifier: MIT

# ==============================================================================
# Script Name: laps_token_minimal.sh (macOS)
# Description: Passes the vault token to golaps over stdin (--secrets-from-stdin)
# so the secret never appears in process arguments or System.keychain.
# ==============================================================================
set -uo pipefail
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

LAPS_VAULT_TOKEN="__VAULT_SERVICE_TOKEN__"
LEGACY_ADMIN_PASS=""
LAPS_BINARY="/usr/local/bin/golaps"

cleanup() {
    unset LAPS_VAULT_TOKEN LEGACY_ADMIN_PASS
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

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

if [ "$LAPS_VAULT_TOKEN" == "__VAULT_SERVICE_TOKEN__" ] || [ -z "$LAPS_VAULT_TOKEN" ]; then
    echo "[ERROR] Vault service token is not configured."
    exit 1
fi

if ! verify_trusted_binary "$LAPS_BINARY"; then
    exit 1
fi

echo "[INFO] Starting GoLAPS rotation process..."
printf '%s\n%s\n' "$LAPS_VAULT_TOKEN" "$LEGACY_ADMIN_PASS" | "$LAPS_BINARY" --secrets-from-stdin
EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo "[SUCCESS] GoLAPS rotation completed successfully."
    exit 0
else
    echo "[ERROR] GoLAPS binary failed with exit code $EXIT_CODE."
    exit 1
fi
