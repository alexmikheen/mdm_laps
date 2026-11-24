#!/bin/bash
# Copyright 2026 Aleksandr Mikheenko
# SPDX-License-Identifier: MIT

# Fleet MDM trigger script for GoLAPS on Linux (runs as root).
# Supports Ubuntu, Debian, RHEL, Fedora, Rocky Linux, and openSUSE.
# Fleet substitutes FLEET_SECRET_* values on the server before execution.
# Set FLEET_SECRET_GOLAPS_LEGACY_PASS to an empty string when not migrating a legacy admin.
set -uo pipefail
export PATH="/usr/sbin:/usr/bin:/sbin:/bin"

LAPS_BINARY="/usr/local/bin/golaps"
STATE_DIR="/var/lib/golaps"
MARKER_PATH="${STATE_DIR}/last_rotation.txt"
TMP_MARKER=""

# Set non-secret defaults if host environment variables are not present.
: "${LAPS_ADMIN_USER:=example-admin}"
: "${LAPS_VAULT_TYPE:=onepassword}"
: "${LAPS_VAULT_ID:=your-vault-id}"
export LAPS_ADMIN_USER LAPS_VAULT_TYPE LAPS_VAULT_ID

# Read Fleet-substituted secrets with single-quoted heredocs to prevent shell expansion.
GOLAPS_SECRET_TOKEN=$(cat <<'__GOLAPS_TOKEN_EOF__'
$FLEET_SECRET_GOLAPS_VAULT_TOKEN
__GOLAPS_TOKEN_EOF__
)

GOLAPS_SECRET_LEGACY=$(cat <<'__GOLAPS_LEGACY_EOF__'
$FLEET_SECRET_GOLAPS_LEGACY_PASS
__GOLAPS_LEGACY_EOF__
)

cleanup() {
    unset GOLAPS_SECRET_TOKEN
    unset GOLAPS_SECRET_LEGACY
    if [ -n "$TMP_MARKER" ] && [ -e "$TMP_MARKER" ]; then
        rm -f "$TMP_MARKER"
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Verify that the binary and every parent directory are root-owned, non-symlink,
# and not writable by group or other.
verify_trusted_binary() {
    local target="$1"
    if [ -L "$target" ] || [ ! -f "$target" ]; then
        echo "[ERROR] $target is missing or a symbolic link." >&2
        return 1
    fi
    local p="$target"
    while :; do
        if [ -L "$p" ]; then
            echo "[ERROR] Untrusted path: $p is a symbolic link." >&2
            return 1
        fi
        local uid mode
        uid=$(stat -c '%u' "$p" 2>/dev/null) || return 1
        mode=$(stat -c '%a' "$p" 2>/dev/null) || return 1
        if [ "$uid" != "0" ]; then
            echo "[ERROR] Untrusted path: $p is owned by uid $uid, not root." >&2
            return 1
        fi
        if [[ ! "$mode" =~ ^[0-7]{3,4}$ ]]; then
            echo "[ERROR] Untrusted path: $p has unexpected mode $mode." >&2
            return 1
        fi
        if (( (8#$mode & 022) != 0 )); then
            echo "[ERROR] Untrusted path: $p is writable by group or other (mode $mode)." >&2
            return 1
        fi
        [ "$p" = "/" ] && break
        p=$(dirname "$p")
    done
    return 0
}

# Abort if placeholder configuration values were left unedited.
if [ -z "$LAPS_ADMIN_USER" ] || [ "$LAPS_ADMIN_USER" = "example-admin" ]; then
    echo "[ERROR] LAPS_ADMIN_USER is empty or still set to the placeholder value 'example-admin'." >&2
    exit 1
fi

if [ -z "$LAPS_VAULT_ID" ] || [ "$LAPS_VAULT_ID" = "your-vault-id" ]; then
    echo "[ERROR] LAPS_VAULT_ID is empty or still set to the placeholder value 'your-vault-id'." >&2
    exit 1
fi

# Abort if the Fleet secret was not substituted or is empty.
# Split the literal marker so Fleet does not substitute inside the check.
if [ -z "$GOLAPS_SECRET_TOKEN" ] || [ "$GOLAPS_SECRET_TOKEN" = '$''FLEET_SECRET_GOLAPS_VAULT_TOKEN' ]; then
    echo "[ERROR] FLEET_SECRET_GOLAPS_VAULT_TOKEN is empty or not configured." >&2
    exit 1
fi

if [ "$GOLAPS_SECRET_LEGACY" = '$''FLEET_SECRET_GOLAPS_LEGACY_PASS' ]; then
    GOLAPS_SECRET_LEGACY=""
fi

# Confirm binary integrity before running GoLAPS as root.
if ! verify_trusted_binary "$LAPS_BINARY"; then
    echo "[ERROR] Refusing to run untrusted binary $LAPS_BINARY." >&2
    exit 1
fi

# Scrub any stray secret or TLS-bypass environment variables before starting GoLAPS.
unset LAPS_VAULT_TOKEN OP_SERVICE_ACCOUNT_TOKEN VAULT_TOKEN \
    BWS_ACCESS_TOKEN BW_API_KEY AZURE_CLIENT_SECRET \
    AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN LEGACY_ADMIN_PASS \
    VAULT_SKIP_VERIFY

echo "[INFO] Starting GoLAPS rotation..."

# Pass secrets over stdin only so they never appear in argv or child environments.
printf '%s\n%s\n' "$GOLAPS_SECRET_TOKEN" "$GOLAPS_SECRET_LEGACY" | "$LAPS_BINARY" --secrets-from-stdin
EXIT_CODE=$?

if [ "$EXIT_CODE" -eq 75 ]; then
    echo "[INFO] GoLAPS skipped rotation (exit 75); leaving last_rotation.txt unchanged."
    exit 0
fi

if [ "$EXIT_CODE" -ne 0 ]; then
    echo "[ERROR] GoLAPS failed with exit code $EXIT_CODE." >&2
    exit "$EXIT_CODE"
fi

# Record rotation timestamp for Fleet osquery compliance policies with hardened permissions.
for dir in "/var" "/var/lib"; do
    if [ -L "$dir" ] || [ ! -d "$dir" ]; then
        echo "[ERROR] Refusing to use untrusted parent state directory: $dir." >&2
        exit 1
    fi
done

if [ -L "$STATE_DIR" ]; then
    echo "[ERROR] Refusing to use symbolic link state directory: $STATE_DIR." >&2
    exit 1
fi

if [ -e "$STATE_DIR" ] && [ ! -d "$STATE_DIR" ]; then
    echo "[ERROR] State path exists and is not a directory: $STATE_DIR." >&2
    exit 1
fi

if [ ! -d "$STATE_DIR" ]; then
    if ! install -d -o root -g root -m 0755 "$STATE_DIR"; then
        echo "[ERROR] Failed to create state directory $STATE_DIR." >&2
        exit 1
    fi
else
    if ! chown root:root "$STATE_DIR" || ! chmod 0755 "$STATE_DIR"; then
        echo "[ERROR] Failed to harden permissions on $STATE_DIR." >&2
        exit 1
    fi
fi

if [ -L "$MARKER_PATH" ]; then
    echo "[ERROR] Refusing to write to symbolic link marker file: $MARKER_PATH." >&2
    exit 1
fi

if [ -e "$MARKER_PATH" ] && [ ! -f "$MARKER_PATH" ]; then
    echo "[ERROR] Marker path exists and is not a regular file: $MARKER_PATH." >&2
    exit 1
fi

TMP_MARKER=$(mktemp "${STATE_DIR}/.last_rotation.XXXXXX") || {
    echo "[ERROR] Failed to create temporary marker file." >&2
    exit 1
}
if ! date -u +"%Y-%m-%dT%H:%M:%SZ" > "$TMP_MARKER" || \
   ! chown root:root "$TMP_MARKER" || \
   ! chmod 0644 "$TMP_MARKER" || \
   ! mv -fT "$TMP_MARKER" "$MARKER_PATH"; then
    echo "[ERROR] Failed to write rotation marker $MARKER_PATH." >&2
    exit 1
fi
TMP_MARKER=""

echo "[SUCCESS] GoLAPS rotation completed."
exit 0
