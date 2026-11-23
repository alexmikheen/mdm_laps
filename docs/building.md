# Building

## Local Build

Run the local build script from the repository root:

```bash
./scripts/build/build.sh
```

The script sets the version in `internal/version/version.go` and `scripts/mdm/macos/audit_laps_customapp.sh`. It then creates a `release/` directory with these artifacts:

- `golaps_windows_amd64.exe` and its `.sha256` checksum
- `golaps_v<version>.pkg` (`golaps`, `mac_helper`, and `golaps_auth`, packaged with `pkgbuild`)

For signed production releases, set `CODESIGN_IDENTITY`, `INSTALLER_IDENTITY`, and `GOLAPS_VERSION` before you run `build.sh`.

## GitHub Actions

The repository includes `.github/workflows/build.yml`.

To build from GitHub:

1. Open the repository on GitHub.
2. Go to **Actions**.
3. Select **Build GoLAPS**.
4. Click **Run workflow**.
5. Download the uploaded build artifacts.

The workflow builds these binaries:

- `golaps_darwin_arm64`
- `golaps_darwin_amd64`
- `golaps_windows_amd64.exe`
- `mac_helper`
