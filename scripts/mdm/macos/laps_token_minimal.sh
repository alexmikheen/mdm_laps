#!/bin/bash
# Copyright 2026 Aleksandr Mikheenko
# SPDX-License-Identifier: GPL-3.0-or-later

# ==============================================================================
# Script Name: LAPS Execution & Keychain Sync (macOS)
# Description: Sends a vault token to macOS Keychain and executes the LAPS updater.
# ==============================================================================

LAPS_VAULT_TOKEN="__VAULT_SERVICE_TOKEN__"
KEYCHAIN="/Library/Keychains/System.keychain"
KEYCHAIN_LABEL="GoLAPS_Vault_Token"
LAPS_BINARY="/usr/local/bin/golaps"

# --- GUARANTEED CLEANUP ---
cleanup() {
    echo "[INFO] Removing token from System Keychain..."
    security delete-generic-password -l "$KEYCHAIN_LABEL" "$KEYCHAIN" >/dev/null 2>&1
}
trap cleanup EXIT INT TERM

if [ "$LAPS_VAULT_TOKEN" == "__VAULT_SERVICE_TOKEN__" ] || [ -z "$LAPS_VAULT_TOKEN" ]; then
    echo "[ERROR] Vault service token is not configured."
    exit 1
fi

# --- 1. TOKEN PROVISIONING (SYSTEM KEYCHAIN) ---
echo "[INFO] Injecting vault service token into System Keychain..."
security delete-generic-password -l "$KEYCHAIN_LABEL" "$KEYCHAIN" >/dev/null 2>&1
security add-generic-password -a "ServiceAccount" -l "$KEYCHAIN_LABEL" -s "GoLAPSVaultToken" -w "$LAPS_VAULT_TOKEN" -A "$KEYCHAIN"
echo "[SUCCESS] Token secured in System Keychain."

# --- 2. EXECUTE THE LAPS UPDATER ---
if [ -f "$LAPS_BINARY" ]; then
    echo "[INFO] Starting LAPS rotation process..."
    "$LAPS_BINARY"
    EXIT_CODE=$?

    if [ $EXIT_CODE -eq 0 ]; then
        echo "[SUCCESS] LAPS rotation completed successfully."
        exit 0
    else
        echo "[ERROR] LAPS binary failed with exit code $EXIT_CODE."
        exit 1
    fi
else
    echo "[ERROR] LAPS binary not found at $LAPS_BINARY."
    exit 1
fi
