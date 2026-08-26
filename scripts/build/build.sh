#!/bin/bash
# ==============================================================================
# Script Name: build.sh
# Description: Automates the compilation of the GoLAPS Updater for macOS (arm64)
# and Windows (amd64). Automatically detects missing Golang dependencies, prompts for official installation, downloads the dependencies at the versions pinned in go.mod, compiles the native Swift helper (mac_helper), and packages the final binaries into a .pkg.
# Logs place: stdout
# Required Permissions: User (Write access), Sudo (only if installing Go)
# ==============================================================================

# ==========================================
# VARIABLES
# ==========================================
PKG_IDENTIFIER="io.github.golaps.mdm-laps"
MAC_ARCH="arm64"
WIN_ARCH="amd64"
RELEASE_DIR="release"

# Single source of truth for where the PKG installs things. The payload is built from these AND they are injected into the audit script, so the two can never drift apart: observed in production, an audit checking a path the payload never delivered made the audit unsatisfiable, and the fleet re-downloaded the package on every check-in while the MDM reported PASS, because the *install* kept succeeding.
MAC_BINARY_PATH="/usr/local/bin/golaps"
MAC_HELPER_PATH="/usr/local/bin/mac_helper"

# ==========================================
# SCRIPT LOGIC
# ==========================================

# Helper function for timestamped INFO logs
log_message() {
    local message="$1"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] [INFO] $message"
}

# Helper function for ERROR logs and safe exit (Fail-safely principle)
log_error_and_exit() {
    local message="$1"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] [ERROR] $message" >&2
    exit 1
}

# Helper function to download and install Go from official sources
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

    log_message "Fetching latest Go version info..."
    local GO_VERSION
    GO_VERSION=$(curl -sSL "https://go.dev/VERSION?m=text" | head -n 1)

    if [ -z "$GO_VERSION" ]; then
        GO_VERSION="go1.22.1" # Safe fallback
        log_message "Failed to fetch latest version, falling back to $GO_VERSION"
    fi

    local DOWNLOAD_URL="https://go.dev/dl/${GO_VERSION}.${OS}-${GO_ARCH}.tar.gz"
    local TMP_DIR
    TMP_DIR=$(mktemp -d)

    log_message "Downloading ${GO_VERSION} from ${DOWNLOAD_URL}..."
    curl -sSL "$DOWNLOAD_URL" -o "${TMP_DIR}/go.tar.gz" || log_error_and_exit "Failed to download Go tarball."

    log_message "Extracting Go to /usr/local... (This requires sudo privileges)"
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "${TMP_DIR}/go.tar.gz" || log_error_and_exit "Failed to extract Go."

    log_message "Creating symlinks in /usr/local/bin so Go is immediately available..."
    sudo ln -sf /usr/local/go/bin/go /usr/local/bin/go
    sudo ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt

    rm -rf "$TMP_DIR"
    log_message "Golang installed successfully! Version: $(go version)"
}

# ==========================================
# VERSION CONTROL & INTERACTIVE PROMPT
# ==========================================
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

if [ -n "$CURRENT_VERSION" ]; then
    echo "📦 Found existing release version in folder: $CURRENT_VERSION"
    read -p "👉 Enter the NEW version number to build [Default: $NEXT_VERSION]: " VERSION
else
    echo "📦 No previous release found in the '$RELEASE_DIR' directory."
    read -p "👉 What is the target VERSION number for this build? [Default: $NEXT_VERSION]: " VERSION
fi
echo "================================================================="

VERSION=${VERSION:-$NEXT_VERSION}

if [[ "$VERSION" == "$CURRENT_VERSION" ]]; then
    log_error_and_exit "You entered '$VERSION', which is the SAME as the current version! Please increment the version number."
fi

log_message "Starting the GoLAPS build process for version $VERSION..."

# ==========================================
# DYNAMIC VERSION INJECTION
# ==========================================

# Rewrites a literal in a source file and then proves the rewrite happened. A silent miss here ships a build that misreports its own version, or an audit script that checks something the package never delivers — either way the MDM reinstalls the PKG on every check-in, forever.
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

# 1. Check for Golang Dependency
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

# 2. Check for Swift Dependency (Required for macOS helper)
if ! command -v swiftc &> /dev/null; then
    log_error_and_exit "Swift compiler (swiftc) not found. Please install Xcode Command Line Tools (xcode-select --install)."
fi

# 3. Initialize Go Modules
log_message "Resolving Go dependencies pinned in go.mod..."
if [ ! -f "go.mod" ]; then
    log_error_and_exit "go.mod not found — run this script from the repository root."
fi

# Download exactly what go.mod pins — `go get` without a version floats a dependency, so two builds of the "same" source could ship different dependency code and a bad upstream release would land in a fleet-wide password tool unnoticed. Bump dependencies deliberately with `go get <module>@vX.Y.Z && go mod tidy`, and commit go.mod/go.sum.
go mod download || log_error_and_exit "Failed to download Go dependencies pinned in go.mod."
go mod verify || log_error_and_exit "Go module checksums do not match go.sum."

# 4. Prepare clean release directory
log_message "Cleaning up old build artifacts..."
rm -rf "$RELEASE_DIR" || log_error_and_exit "Failed to remove old release directory."
PAYLOAD_ROOT="$RELEASE_DIR/payload"
mkdir -p "$PAYLOAD_ROOT$(dirname "$MAC_BINARY_PATH")" || log_error_and_exit "Failed to create payload directory."

# 5. Compile Swift Helper (macOS Native Cryptographic Operations)
log_message "Compiling Swift Helper (mac_helper)..."
# -O flag optimizes the binary, -target ensures backward compatibility with older macOS versions
swiftc internal/osmgmt/mac_helper.swift -target arm64-apple-macosx12.0 -o "$PAYLOAD_ROOT$MAC_HELPER_PATH" -O || log_error_and_exit "Swift compilation failed!"

# 6. Compile Go Binary for Windows
log_message "Compiling for Windows ($WIN_ARCH)..."
GOOS=windows GOARCH=$WIN_ARCH go build -ldflags="-s -w" -o "$RELEASE_DIR/golaps_windows_${WIN_ARCH}.exe" ./cmd || log_error_and_exit "Windows compilation failed!"

# Publish a checksum beside the .exe. A Windows launcher that downloads this binary and runs it as SYSTEM on every device should refuse to install one whose SHA-256 it cannot verify. Publish BOTH files together — the .exe alone should be rejected by such a launcher.
(cd "$RELEASE_DIR" && shasum -a 256 "golaps_windows_${WIN_ARCH}.exe" > "golaps_windows_${WIN_ARCH}.exe.sha256") || log_error_and_exit "Failed to generate the Windows binary checksum."

# 7. Compile Go Binary for macOS
log_message "Compiling for macOS ($MAC_ARCH)..."
GOOS=darwin GOARCH=$MAC_ARCH go build -ldflags="-s -w" -o "$PAYLOAD_ROOT$MAC_BINARY_PATH" ./cmd || log_error_and_exit "macOS compilation failed!"

# Ensure proper execution permissions (Principle of Least Privilege)
chmod +x "$PAYLOAD_ROOT$MAC_BINARY_PATH" || log_error_and_exit "Failed to set executable permissions for golaps."
chmod +x "$PAYLOAD_ROOT$MAC_HELPER_PATH" || log_error_and_exit "Failed to set executable permissions for mac_helper."

# Prove the package really delivers what the audit script was told to look for.
[ -f "$PAYLOAD_ROOT$MAC_BINARY_PATH" ] || log_error_and_exit "Payload is missing $MAC_BINARY_PATH — the audit script would never pass."

# 8. Package macOS binaries into .pkg
log_message "Packaging macOS binaries into .pkg..."
if command -v pkgbuild &> /dev/null; then
    pkgbuild --root "$PAYLOAD_ROOT" --identifier "$PKG_IDENTIFIER" --version "$VERSION" "$RELEASE_DIR/golaps_v${VERSION}.pkg" > /dev/null 2>&1 || log_error_and_exit "pkgbuild failed!"
else
    log_error_and_exit "'pkgbuild' command not found. This script must be run on macOS to generate the .pkg file."
fi

# Cleanup
rm -rf "$PAYLOAD_ROOT"

echo "===================================================="
log_message "Build successfully completed for Version $VERSION!"
echo "Files ready in '$RELEASE_DIR' directory:"
ls -lh "$RELEASE_DIR/"
echo "===================================================="
exit 0
