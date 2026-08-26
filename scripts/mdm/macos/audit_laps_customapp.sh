#!/bin/bash
# Copyright 2026 Aleksandr Mikheenko
# SPDX-License-Identifier: GPL-3.0-or-later

# Script Name: audit.sh
# Description: Audits the LAPS Updater installation by verifying the macOS package receipt. Returns 1 if the expected version is not installed, allowing your MDM to deploy the attached PKG.
# Logs place: stdout (captured by MDM)
# Required Permissions: root

# ==========================================
# VARIABLES
# ==========================================
BINARY_PATH="/usr/local/bin/golaps"
PKG_ID="io.github.golaps.mdm-laps"
# Rewritten by scripts/build/build.sh on every release
EXPECTED_VERSION="0.0.0"

# ==========================================
# SCRIPT_LOGIC
# ==========================================

# Function to write timestamped INFO logs
log_message() {
    local message="$1"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] [INFO] $message"
}

log_message "Starting local Audit for LAPS Updater..."

# 1. The macOS receipt database is the authority on what is installed. The on-disk file check comes AFTER it, deliberately: when a missing file was tested first, a wrong BINARY_PATH made the audit unsatisfiable, and the MDM answered every failure by reinstalling a package that was already installed correctly — forever, while reporting PASS because the install itself kept succeeding. awk '{print $2}' extracts just the version number from "version: 1.0"
INSTALLED_VERSION=$(pkgutil --pkg-info "$PKG_ID" 2>/dev/null | grep -i "^version: " | awk '{print $2}')

if [ -z "$INSTALLED_VERSION" ]; then
    log_message "PKG receipt not found for $PKG_ID. Installation required."
    exit 1 # Triggers the MDM to install the PKG
fi

log_message "Installed version: $INSTALLED_VERSION | Expected version: $EXPECTED_VERSION"

# 2. Compare versions
if [ "$INSTALLED_VERSION" != "$EXPECTED_VERSION" ]; then
    log_message "ACTION REQUIRED: Version mismatch. Triggering the MDM to install the new PKG."
    exit 1 # Triggers the MDM to install the new PKG
fi

# 3. The receipt claims the right version. If the binary is missing anyway, reinstalling will not help — the receipt and the payload disagree, and that is the state that produces a silent reinstall loop. Say so explicitly instead of asking for the same package again.
if [ ! -f "$BINARY_PATH" ]; then
    log_message "ERROR: receipt/payload mismatch. $PKG_ID $INSTALLED_VERSION is registered as installed, but $BINARY_PATH does not exist."
    log_message "Reinstalling will not fix this. Verify the PKG payload really delivers $BINARY_PATH, then clear the stale receipt with: pkgutil --forget $PKG_ID"
    exit 1
fi

log_message "SUCCESS: The correct version ($EXPECTED_VERSION) is installed at $BINARY_PATH."
exit 0 # All good, the MDM does nothing
