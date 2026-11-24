#!/bin/bash
# Copyright 2026 Aleksandr Mikheenko
# SPDX-License-Identifier: MIT

# Fleet software install script for GoLAPS on Linux (runs as root).
# Fleet extracts .tar.gz packages and passes the extracted directory as INSTALLER_PATH.
# A .tar.gz file path is also accepted for manual runs.
set -euo pipefail
export PATH="/usr/sbin:/usr/bin:/sbin:/bin"

INSTALL_DIR="/usr/local/bin"
TARGET_PATH="${INSTALL_DIR}/golaps"
EXTRACT_DIR=""
TMP_TARGET=""

cleanup() {
    if [ -n "$TMP_TARGET" ] && [ -e "$TMP_TARGET" ]; then
        rm -f "$TMP_TARGET"
    fi
    if [ -n "$EXTRACT_DIR" ] && [ -d "$EXTRACT_DIR" ]; then
        rm -rf "$EXTRACT_DIR"
    fi
}
trap cleanup EXIT

if [ -z "${INSTALLER_PATH:-}" ] || [ -L "$INSTALLER_PATH" ]; then
    echo "[ERROR] INSTALLER_PATH is missing or a symbolic link." >&2
    exit 1
fi

for dir in "/usr" "/usr/local"; do
    if [ -L "$dir" ] || [ ! -d "$dir" ]; then
        echo "[ERROR] Refusing to install through untrusted parent directory: $dir." >&2
        exit 1
    fi
done

if [ -L "$INSTALL_DIR" ]; then
    echo "[ERROR] Refusing to install into symbolic link directory: $INSTALL_DIR." >&2
    exit 1
fi

if [ -e "$INSTALL_DIR" ] && [ ! -d "$INSTALL_DIR" ]; then
    echo "[ERROR] Install path exists and is not a directory: $INSTALL_DIR." >&2
    exit 1
fi

if [ ! -d "$INSTALL_DIR" ]; then
    install -d -o root -g root -m 0755 "$INSTALL_DIR"
else
    chown root:root "$INSTALL_DIR"
    chmod 0755 "$INSTALL_DIR"
fi

if [ -L "$TARGET_PATH" ]; then
    echo "[ERROR] Refusing to overwrite symbolic link binary: $TARGET_PATH." >&2
    exit 1
fi

if [ -e "$TARGET_PATH" ] && [ ! -f "$TARGET_PATH" ]; then
    echo "[ERROR] Target path exists and is not a regular file: $TARGET_PATH." >&2
    exit 1
fi

if [ -d "$INSTALLER_PATH" ]; then
    SRC_BIN="${INSTALLER_PATH}/golaps"
elif [ -f "$INSTALLER_PATH" ]; then
    EXTRACT_DIR=$(mktemp -d)
    tar -xzf "$INSTALLER_PATH" -C "$EXTRACT_DIR" --no-same-owner --no-same-permissions golaps
    SRC_BIN="${EXTRACT_DIR}/golaps"
else
    echo "[ERROR] INSTALLER_PATH is neither a directory nor a regular file: $INSTALLER_PATH." >&2
    exit 1
fi

if [ -L "$SRC_BIN" ] || [ ! -f "$SRC_BIN" ]; then
    echo "[ERROR] Source golaps binary is missing, a symbolic link, or not a regular file: $SRC_BIN." >&2
    exit 1
fi

TMP_TARGET=$(mktemp "${INSTALL_DIR}/.golaps.XXXXXX")
install -o root -g root -m 0755 "$SRC_BIN" "$TMP_TARGET"
mv -fT "$TMP_TARGET" "$TARGET_PATH"
TMP_TARGET=""

echo "[SUCCESS] Installed GoLAPS to $TARGET_PATH."
exit 0
