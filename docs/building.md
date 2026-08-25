# Building

## Local Build

Run the local build script from the repository root:

```bash
./scripts/build/build.sh
```

The script asks for a version number, injects it into `internal/version/version.go` and the MDM
audit script, and creates a `release/` directory with:

- `golaps_windows_amd64.exe` + `.sha256` checksum
- `golaps_v<version>.pkg` (macOS binary + Swift helper, built with `pkgbuild`)

## GitHub Actions

The repository includes `.github/workflows/build.yml`.

To build from GitHub:

1. Open the repository on GitHub.
2. Go to **Actions**.
3. Select **Build GoLAPS**.
4. Click **Run workflow**.
5. Download the uploaded build artifacts.

The workflow builds:

- `golaps_darwin_arm64`
- `golaps_darwin_amd64`
- `golaps_windows_amd64.exe`
- `mac_helper`
