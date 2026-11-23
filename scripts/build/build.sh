#!/bin/bash
# Copyright 2026 Aleksandr Mikheenko
# SPDX-License-Identifier: MIT

# Build GoLAPS for macOS (arm64) and Windows (amd64) and package the macOS .pkg.

PKG_IDENTIFIER="io.github.golaps.mdm-laps"
MAC_ARCH="arm64"
WIN_ARCH="amd64"
RELEASE_DIR="release"

# Install paths shared by the .pkg payload and audit_laps_customapp.sh.
MAC_BINARY_PATH="/usr/local/bin/golaps"
MAC_HELPER_PATH="/usr/local/bin/mac_helper"
MAC_AUTH_WINDOW_PATH="/usr/local/bin/golaps_auth"
MAC_BACKDROP_PATH="/usr/local/golaps/backdrop.jpg"
BACKDROP_SOURCE="assets/backdrop.jpg"

log_message() {
    local message="$1"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] [INFO] $message"
}

log_error_and_exit() {
    local message="$1"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] [ERROR] $message" >&2
    exit 1
}

install_go() {
    log_message "Detecting system architecture for Go installation..."

    local OS
    local ARCH
    local GO_ARCH

    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    if [ "$ARCH" = "x86_64" ]; then
        GO_ARCH="amd64"
    elif [ "$ARCH" = "arm64" ] || [ "$ARCH" = "aarch64" ]; then
        GO_ARCH="arm64"
    else
        log_error_and_exit "Unsupported architecture for automated Go install: $ARCH"
    fi

    local GO_VERSION
    GO_VERSION=$(awk '/^toolchain go[0-9]/ {print $2; exit}' go.mod)
    if [ -z "$GO_VERSION" ]; then
        GO_VERSION=$(curl -sSL "https://go.dev/VERSION?m=text" | head -n 1)
    fi
    [ -n "$GO_VERSION" ] || log_error_and_exit "Could not determine target Go version."

    local TARBALL="${GO_VERSION}.${OS}-${GO_ARCH}.tar.gz"
    local DOWNLOAD_URL="https://go.dev/dl/${TARBALL}"
    local TMP_DIR
    TMP_DIR=$(mktemp -d)
    trap 'rm -rf "'"$TMP_DIR"'"' RETURN EXIT

    log_message "Fetching official go.dev checksum for ${TARBALL}..."
    curl -sSL "https://go.dev/dl/?mode=json&include=all" -o "${TMP_DIR}/releases.json" || log_error_and_exit "Failed to fetch go.dev release metadata."
    local EXPECTED_SHA256
    EXPECTED_SHA256=$(python3 -I - "${TMP_DIR}/releases.json" "$GO_VERSION" "$OS" "$GO_ARCH" <<'PY'
import json, sys
listing, version, os_name, arch = sys.argv[1:5]
with open(listing, encoding="utf-8") as handle:
    releases = json.load(handle)
for release in releases:
    if release.get("version") != version:
        continue
    for file in release.get("files", []):
        if file.get("os") == os_name and file.get("arch") == arch and file.get("kind") == "archive":
            print(file["sha256"])
            sys.exit(0)
sys.exit(1)
PY
    ) || log_error_and_exit "${GO_VERSION} for ${OS}/${GO_ARCH} not found in go.dev release listing."
    [[ "$EXPECTED_SHA256" =~ ^[0-9a-f]{64}$ ]] || log_error_and_exit "Invalid SHA-256 from go.dev listing."

    log_message "Downloading ${GO_VERSION} from ${DOWNLOAD_URL}..."
    curl -sSL "$DOWNLOAD_URL" -o "${TMP_DIR}/go.tar.gz" || log_error_and_exit "Failed to download Go tarball."

    local ACTUAL_SHA256
    ACTUAL_SHA256=$(shasum -a 256 "${TMP_DIR}/go.tar.gz" | awk '{print $1}')
    [ "$ACTUAL_SHA256" = "$EXPECTED_SHA256" ] || log_error_and_exit "SHA-256 mismatch for ${TARBALL} (got ${ACTUAL_SHA256}, expected ${EXPECTED_SHA256})."
    log_message "SHA-256 verified for ${TARBALL}."

    log_message "Extracting Go to /usr/local... (This requires sudo privileges)"
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "${TMP_DIR}/go.tar.gz" || log_error_and_exit "Failed to extract Go."

    log_message "Creating symlinks in /usr/local/bin so Go is immediately available..."
    sudo ln -sf /usr/local/go/bin/go /usr/local/bin/go
    sudo ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt

    rm -rf "$TMP_DIR"
    trap - RETURN EXIT
    log_message "Golang installed successfully! Version: $(go version)"
}

echo "================================================================="
log_message "Checking for previous builds..."
CURRENT_VERSION=""
NEXT_VERSION="1.0.0"

if [ -d "$RELEASE_DIR" ]; then
    EXISTING_FILE=$(ls "$RELEASE_DIR" 2>/dev/null | grep -E 'v[0-9]+\.[0-9]+\.[0-9]+\.(pkg|exe)' | head -n 1)
    if [ -n "$EXISTING_FILE" ]; then
        CURRENT_VERSION=$(echo "$EXISTING_FILE" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n 1)
        NEXT_VERSION=$(echo "$CURRENT_VERSION" | awk -F. -v OFS=. '{$NF += 1 ; print}')
    fi
fi

if [ -n "${GOLAPS_VERSION:-}" ]; then
    VERSION="$GOLAPS_VERSION"
    log_message "Using target version from GOLAPS_VERSION: $VERSION"
elif [ -n "$CURRENT_VERSION" ]; then
    echo "📦 Found existing release version in folder: $CURRENT_VERSION"
    read -p "👉 Enter the NEW version number to build [Default: $NEXT_VERSION]: " VERSION
else
    echo "📦 No previous release found in the '$RELEASE_DIR' directory."
    read -p "👉 What is the target VERSION number for this build? [Default: $NEXT_VERSION]: " VERSION
fi
echo "================================================================="

VERSION=${VERSION:-$NEXT_VERSION}

if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    log_error_and_exit "Invalid version '$VERSION' (expected MAJOR.MINOR.PATCH, e.g. 1.0.0)."
fi

if [[ "$VERSION" == "$CURRENT_VERSION" ]]; then
    log_error_and_exit "You entered '$VERSION', which is the SAME as the current version! Please increment the version number."
fi

if { [ -n "${CODESIGN_IDENTITY:-}" ] && [ -z "${INSTALLER_IDENTITY:-}" ]; } || { [ -z "${CODESIGN_IDENTITY:-}" ] && [ -n "${INSTALLER_IDENTITY:-}" ]; }; then
    log_error_and_exit "Set BOTH CODESIGN_IDENTITY and INSTALLER_IDENTITY together (or neither for an unsigned local build)."
fi

log_message "Starting the GoLAPS build process for version $VERSION..."

# Rewrite a literal in a file and fail if the expected pattern did not match.
inject_version() {
    local file="$1"
    local expression="$2"
    local expected="$3"

    [ -f "$file" ] || log_error_and_exit "Cannot inject version: $file not found."
    sed -i '' -E "$expression" "$file" || log_error_and_exit "Failed to inject version $VERSION into $file."
    grep -qF "$expected" "$file" || log_error_and_exit "Version injection into $file did not take effect (expected: $expected)."
    log_message "  $file -> $expected"
}

log_message "Injecting version $VERSION..."
inject_version "internal/version/version.go" \
    "s/const Version = \"[^\"]+\"/const Version = \"$VERSION\"/" \
    "const Version = \"$VERSION\""
inject_version "scripts/mdm/macos/audit_laps_customapp.sh" \
    "s/^EXPECTED_VERSION=\"[^\"]*\"/EXPECTED_VERSION=\"$VERSION\"/" \
    "EXPECTED_VERSION=\"$VERSION\""
inject_version "scripts/mdm/macos/audit_laps_customapp.sh" \
    "s|^BINARY_PATH=\"[^\"]*\"|BINARY_PATH=\"$MAC_BINARY_PATH\"|" \
    "BINARY_PATH=\"$MAC_BINARY_PATH\""

if ! command -v go &> /dev/null; then
    echo "================================================================="
    echo "⚠️  Golang is not installed or not in your PATH."
    echo "================================================================="
    read -p "Would you like this script to download and install Go automatically from go.dev? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        install_go
    else
        log_error_and_exit "Compilation aborted. Please install Golang manually to proceed."
    fi
else
    log_message "Golang is installed: $(go version)"
fi

if ! command -v swiftc &> /dev/null; then
    log_error_and_exit "Swift compiler (swiftc) not found. Please install Xcode Command Line Tools (xcode-select --install)."
fi

log_message "Resolving Go dependencies pinned in go.mod..."
if [ ! -f "go.mod" ]; then
    log_error_and_exit "go.mod not found — run this script from the repository root."
fi

# Download exact pinned module versions from go.mod without floating upgrades.
go mod download || log_error_and_exit "Failed to download Go dependencies pinned in go.mod."
go mod verify || log_error_and_exit "Go module checksums do not match go.sum."

log_message "Cleaning up old build artifacts..."
rm -rf "$RELEASE_DIR" || log_error_and_exit "Failed to remove old release directory."
PAYLOAD_ROOT="$RELEASE_DIR/payload"
mkdir -p "$PAYLOAD_ROOT$(dirname "$MAC_BINARY_PATH")" || log_error_and_exit "Failed to create payload directory."

log_message "Compiling Swift Helper (mac_helper)..."
swiftc internal/osmgmt/mac_helper.swift -target arm64-apple-macosx12.0 -o "$PAYLOAD_ROOT$MAC_HELPER_PATH" -O || log_error_and_exit "Swift compilation failed!"

log_message "Compiling native password window (golaps_auth)..."
swiftc internal/osmgmt/auth_window.swift -target arm64-apple-macosx12.0 -o "$PAYLOAD_ROOT$MAC_AUTH_WINDOW_PATH" -O || log_error_and_exit "Swift compilation of the password window failed!"

log_message "Compiling for Windows ($WIN_ARCH)..."
GOOS=windows GOARCH=$WIN_ARCH go build -trimpath -ldflags="-s -w" -o "$RELEASE_DIR/golaps_windows_${WIN_ARCH}.exe" ./cmd || log_error_and_exit "Windows compilation failed!"

# Publish the SHA-256 checksum alongside the Windows executable.
(cd "$RELEASE_DIR" && shasum -a 256 "golaps_windows_${WIN_ARCH}.exe" > "golaps_windows_${WIN_ARCH}.exe.sha256") || log_error_and_exit "Failed to generate the Windows binary checksum."

log_message "Compiling for macOS ($MAC_ARCH)..."
GOOS=darwin GOARCH=$MAC_ARCH go build -trimpath -ldflags="-s -w" -o "$PAYLOAD_ROOT$MAC_BINARY_PATH" ./cmd || log_error_and_exit "macOS compilation failed!"

find "$PAYLOAD_ROOT" -type d -exec chmod 755 {} + || log_error_and_exit "Failed to set directory permissions in payload."
chmod 755 "$PAYLOAD_ROOT$MAC_BINARY_PATH" || log_error_and_exit "Failed to set executable permissions for golaps."
chmod 755 "$PAYLOAD_ROOT$MAC_HELPER_PATH" || log_error_and_exit "Failed to set executable permissions for mac_helper."
chmod 755 "$PAYLOAD_ROOT$MAC_AUTH_WINDOW_PATH" || log_error_and_exit "Failed to set executable permissions for golaps_auth."

if [ -f "$BACKDROP_SOURCE" ]; then
    mkdir -p "$PAYLOAD_ROOT$(dirname "$MAC_BACKDROP_PATH")" || log_error_and_exit "Failed to create the backdrop directory."
    chmod 755 "$PAYLOAD_ROOT$(dirname "$MAC_BACKDROP_PATH")" || log_error_and_exit "Failed to set the mode of the backdrop directory."
    cp "$BACKDROP_SOURCE" "$PAYLOAD_ROOT$MAC_BACKDROP_PATH" || log_error_and_exit "Failed to copy the backdrop picture."
    chmod 644 "$PAYLOAD_ROOT$MAC_BACKDROP_PATH" || log_error_and_exit "Failed to set the mode of the backdrop picture."
    log_message "Backdrop picture added to the payload."
else
    log_message "INFO: $BACKDROP_SOURCE not found. The package ships without a backdrop picture (plain dark backdrop)."
fi

[ -f "$PAYLOAD_ROOT$MAC_BINARY_PATH" ] || log_error_and_exit "Payload is missing $MAC_BINARY_PATH — the audit script would never pass."

# Sign macOS binaries with explicit bundle IDs and Hardened Runtime.
# Set CODESIGN_IDENTITY and INSTALLER_IDENTITY for production MDM releases.
sign_binary() {
    local bin="$1"
    local ident="$2"
    if [ -n "${CODESIGN_IDENTITY:-}" ]; then
        codesign --force --options runtime --timestamp --identifier "$ident" --sign "$CODESIGN_IDENTITY" "$bin" || log_error_and_exit "codesign failed for $bin"
    else
        codesign --force --options runtime --identifier "$ident" --sign - "$bin" || log_error_and_exit "ad-hoc codesign failed for $bin"
    fi
}

if [ -n "${CODESIGN_IDENTITY:-}" ]; then
    log_message "Signing macOS binaries with Hardened Runtime ($CODESIGN_IDENTITY)..."
else
    log_message "WARNING: CODESIGN_IDENTITY is not set. Applying ad-hoc Hardened Runtime signature; set CODESIGN_IDENTITY and INSTALLER_IDENTITY for production releases."
fi

sign_binary "$PAYLOAD_ROOT$MAC_BINARY_PATH" "io.github.golaps.golaps"
sign_binary "$PAYLOAD_ROOT$MAC_HELPER_PATH" "io.github.golaps.mac-helper"
sign_binary "$PAYLOAD_ROOT$MAC_AUTH_WINDOW_PATH" "io.github.golaps.auth-window"

# Stage payload with ditto --norsrc --noextattr so the .pkg BOM contains no AppleDouble (._*) files.
STAGE_ROOT="$RELEASE_DIR/pkg_stage"
rm -rf "$STAGE_ROOT"
ditto --norsrc --noextattr "$PAYLOAD_ROOT/usr/local" "$STAGE_ROOT" || log_error_and_exit "Failed to stage clean payload with ditto."
find "$STAGE_ROOT" -name '._*' -delete
xattr -cr "$STAGE_ROOT" 2>/dev/null || true
export COPYFILE_DISABLE=1

# Scope the .pkg to /usr/local with --ownership recommended so / and /usr stay out of the BOM.
log_message "Packaging macOS binaries into .pkg..."
PKG_OUT="$RELEASE_DIR/golaps_v${VERSION}.pkg"
if command -v pkgbuild &> /dev/null; then
    if [ -n "${INSTALLER_IDENTITY:-}" ]; then
        COPYFILE_DISABLE=1 pkgbuild --root "$STAGE_ROOT" --install-location /usr/local --ownership recommended --identifier "$PKG_IDENTIFIER" --version "$VERSION" "$RELEASE_DIR/golaps_v${VERSION}_unsigned.pkg" > /dev/null 2>&1 || log_error_and_exit "pkgbuild failed!"
        productsign --sign "$INSTALLER_IDENTITY" --timestamp "$RELEASE_DIR/golaps_v${VERSION}_unsigned.pkg" "$PKG_OUT" || log_error_and_exit "productsign failed!"
        rm -f "$RELEASE_DIR/golaps_v${VERSION}_unsigned.pkg"
    else
        COPYFILE_DISABLE=1 pkgbuild --root "$STAGE_ROOT" --install-location /usr/local --ownership recommended --identifier "$PKG_IDENTIFIER" --version "$VERSION" "$PKG_OUT" > /dev/null 2>&1 || log_error_and_exit "pkgbuild failed!"
    fi
else
    log_error_and_exit "'pkgbuild' command not found. This script must be run on macOS to generate the .pkg file."
fi

if pkgutil --payload-files "$PKG_OUT" | grep -q '/\._'; then
    if [ -n "${INSTALLER_IDENTITY:-}" ]; then
        log_error_and_exit "Package BOM contains AppleDouble (._*) files (likely macOS com.apple.provenance from a sandboxed terminal). Build production releases from a native Terminal or CI runner."
    fi
    log_message "WARNING: Package BOM contains AppleDouble (._*) files (likely macOS com.apple.provenance from a sandboxed terminal). Build production releases from a native Terminal or CI runner."
fi

rm -rf "$PAYLOAD_ROOT" "$STAGE_ROOT"

echo "===================================================="
log_message "Build successfully completed for Version $VERSION!"
echo "Files ready in '$RELEASE_DIR' directory:"
ls -lh "$RELEASE_DIR/"
echo "===================================================="
exit 0
