#!/bin/bash
# Copyright 2026 Aleksandr Mikheenko
# SPDX-License-Identifier: MIT

# MDM audit script: exits 0 when the expected GoLAPS package version and binary exist.
PKG_ID="io.github.golaps.mdm-laps"
BINARY_PATH="/usr/local/bin/golaps"
# Rewritten by scripts/build/build.sh on every release
EXPECTED_VERSION="0.0.0"

log_message() {
    local message="$1"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] [INFO] $message"
}

log_message "Starting local Audit for LAPS Updater..."

# Check the macOS receipt database before checking disk paths to avoid reinstall loops.
INSTALLED_VERSION=$(pkgutil --pkg-info "$PKG_ID" 2>/dev/null | grep -i "^version: " | awk '{print $2}')

if [ -z "$INSTALLED_VERSION" ]; then
    log_message "PKG receipt not found for $PKG_ID. Installation required."
    exit 1 # Triggers the MDM to install the PKG
fi

log_message "Installed version: $INSTALLED_VERSION | Expected version: $EXPECTED_VERSION"

if [ "$INSTALLED_VERSION" != "$EXPECTED_VERSION" ]; then
    log_message "ACTION REQUIRED: Version mismatch. Triggering the MDM to install the new PKG."
    exit 1 # Triggers the MDM to install the new PKG
fi

# Fail loudly if the receipt matches but the binary is missing on disk.
if [ ! -f "$BINARY_PATH" ]; then
    log_message "ERROR: receipt/payload mismatch. $PKG_ID $INSTALLED_VERSION is registered as installed, but $BINARY_PATH does not exist."
    log_message "Reinstalling will not fix this. Verify the PKG payload really delivers $BINARY_PATH, then clear the stale receipt with: pkgutil --forget $PKG_ID"
    exit 1
fi

log_message "SUCCESS: The correct version ($EXPECTED_VERSION) is installed at $BINARY_PATH."
exit 0 # All good, the MDM does nothing
