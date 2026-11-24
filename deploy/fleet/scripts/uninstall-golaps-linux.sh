#!/bin/bash
# Copyright 2026 Aleksandr Mikheenko
# SPDX-License-Identifier: MIT

# Fleet software uninstall script for GoLAPS on Linux (runs as root).
set -euo pipefail
export PATH="/usr/sbin:/usr/bin:/sbin:/bin"

TARGET_PATH="/usr/local/bin/golaps"

for dir in "/usr" "/usr/local" "/usr/local/bin"; do
    if [ -L "$dir" ] || [ ! -d "$dir" ]; then
        echo "[ERROR] Refusing to uninstall through untrusted parent directory: $dir." >&2
        exit 1
    fi
done

if [ -L "$TARGET_PATH" ]; then
    echo "[ERROR] Refusing to remove symbolic link binary: $TARGET_PATH." >&2
    exit 1
fi

if [ -e "$TARGET_PATH" ]; then
    if [ ! -f "$TARGET_PATH" ]; then
        echo "[ERROR] Target path exists and is not a regular file: $TARGET_PATH." >&2
        exit 1
    fi
    rm -f "$TARGET_PATH"
fi

echo "[SUCCESS] Uninstalled GoLAPS from $TARGET_PATH."
exit 0
