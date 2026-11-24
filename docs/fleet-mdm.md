# Fleet MDM Integration

Use GoLAPS with [Fleet](https://fleetdm.com) to manage local administrator passwords on macOS, Windows, and Linux hosts.

## Why Use GoLAPS with Fleet MDM

- **Works on Fleet Free and Fleet Premium**: Software packages, configuration profiles, scripts, and osquery policies work on Fleet Free. Automatic policy remediation with `run_script` requires Fleet Premium.
- **External vault escrow**: GoLAPS supports 1Password, HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, and Bitwarden Secrets Manager. It writes the new credential to the vault before it rotates the device password. See [configuration.md](configuration.md) for provider settings.
- **Brownfield non-ADE Macs**: GoLAPS does not require Automated Device Enrollment (ADE). It manages local administrator accounts on existing macOS, Windows, and Linux devices.
- **Apple Silicon Secure Token recovery**: When a silent grant fails, GoLAPS opens the native SwiftUI window (`/usr/local/bin/golaps_auth`) to collect a local administrator credential. It also supports Admin By Request elevation ([admin-by-request.md](admin-by-request.md)).

## GitOps Bundle Files

The [deploy/fleet](../deploy/fleet) directory contains a Fleet 5 GitOps bundle:

- [fleet-golaps.yml](../deploy/fleet/fleet-golaps.yml) — Fleet configuration for packages, profiles, scripts, and policies.
- [run-golaps-macos.sh](../deploy/fleet/scripts/run-golaps-macos.sh) — macOS trigger script.
- [run-golaps-windows.ps1](../deploy/fleet/scripts/run-golaps-windows.ps1) — Windows trigger script.
- [install-golaps-windows.ps1](../deploy/fleet/scripts/install-golaps-windows.ps1) — Windows Fleet package install script.
- [run-golaps-linux.sh](../deploy/fleet/scripts/run-golaps-linux.sh) — Linux trigger script.
- [install-golaps-linux.sh](../deploy/fleet/scripts/install-golaps-linux.sh) — Linux Fleet package install script.
- [uninstall-golaps-linux.sh](../deploy/fleet/scripts/uninstall-golaps-linux.sh) — Linux Fleet package uninstall script.
- [golaps-policies.yml](../deploy/fleet/policies/golaps-policies.yml) — osquery compliance and remediation policies.
- [admin_config.mobileconfig](../profiles/macos/admin_config.mobileconfig) — macOS managed preferences profile for the `io.github.golaps` domain.

## Setup with `fleetctl gitops`

1. Build the macOS `.pkg`, Windows `.exe`, and Linux `.tar.gz` artifacts with `./scripts/build/build.sh`.
2. Host the release files on an HTTPS server and record their SHA-256 hashes.
3. Open [deploy/fleet/fleet-golaps.yml](../deploy/fleet/fleet-golaps.yml) and set the fleet `name`, package `url` values, and `hash_sha256` values. The example bundle targets `golaps_linux_amd64.tar.gz`. Add a separate package entry or fleet for Linux `arm64` hosts.
4. Edit [profiles/macos/admin_config.mobileconfig](../profiles/macos/admin_config.mobileconfig) to set `AdminUser`, `VaultID`, `VaultType`, and `PasswordLength`.
5. Replace `example-admin` in [deploy/fleet/policies/golaps-policies.yml](../deploy/fleet/policies/golaps-policies.yml) with your managed administrator name.
6. Update the fallback `LAPS_ADMIN_USER`, `LAPS_VAULT_TYPE`, and `LAPS_VAULT_ID` values in [deploy/fleet/scripts/run-golaps-windows.ps1](../deploy/fleet/scripts/run-golaps-windows.ps1) and [deploy/fleet/scripts/run-golaps-linux.sh](../deploy/fleet/scripts/run-golaps-linux.sh) if hosts do not set environment variables.
7. Export the required Fleet secret variables in your shell or CI runner:

```bash
export FLEET_SECRET_GOLAPS_VAULT_TOKEN="your-vault-token"
export FLEET_SECRET_GOLAPS_LEGACY_PASS=""
```

Set `FLEET_SECRET_GOLAPS_LEGACY_PASS` to an empty string when you do not migrate a legacy administrator account.

8. Check the configuration against your Fleet server:

```bash
fleetctl gitops -f deploy/fleet/fleet-golaps.yml --dry-run
```

9. Apply the GitOps configuration:

```bash
fleetctl gitops -f deploy/fleet/fleet-golaps.yml
```

Fleet 5 places macOS configuration profiles under `controls.apple_settings.configuration_profiles`. Fleet rejects the removed `controls.macos_settings.custom_settings` key.

## Automated Remediation with osquery Policies

[deploy/fleet/policies/golaps-policies.yml](../deploy/fleet/policies/golaps-policies.yml) defines six osquery policies:

1. **GoLAPS - macOS binary installed**: Checks that `/usr/local/bin/golaps` exists as a regular file in the `file` table.
2. **GoLAPS - macOS managed admin holds Secure Token and rotated recently**: Joins `/var/db/dslocal/nodes/Default/users/example-admin.plist` (`authentication_authority` contains `SecureToken`) with `/Library/Logs/golaps.log` modified within the last 30 days (`2592000` seconds). On failure, Fleet runs `../scripts/run-golaps-macos.sh`.
3. **GoLAPS - Windows binary installed**: Checks that `C:\Program Files\GoLAPS\golaps.exe` exists as a regular file in the `file` table.
4. **GoLAPS - Windows managed admin exists in Administrators and rotated recently**: Checks that the managed administrator belongs to `Administrators` (`S-1-5-32-544`) and that `C:\ProgramData\GoLAPS\last_rotation.txt` updated within the last 30 days. On failure, Fleet runs `../scripts/run-golaps-windows.ps1`.
5. **GoLAPS - Linux binary installed**: Checks that `/usr/local/bin/golaps` exists as a regular file in the `file` table.
6. **GoLAPS - Linux managed admin exists in sudo or wheel and rotated recently**: Checks that the managed admin is in `sudo` or `wheel`. It also checks that `/var/lib/golaps/last_rotation.txt` updated within 30 days. On failure, Fleet runs `../scripts/run-golaps-linux.sh`.

Each `run_script.path` value is relative to the policy YAML file and must match an entry in `controls.scripts` of the same fleet.

On Fleet Premium, a failing policy triggers the linked script automatically. On Fleet Free, the same policies report non-compliant hosts, and operators run the scripts from the host Scripts tab or the Fleet API.

## Security Notes

- **No tokens in Git**: Never commit real vault tokens, legacy passwords, or `.env` files to Git. During `fleetctl gitops`, Fleet reads `$FLEET_SECRET_*` variables from your local shell or CI environment, stores them on the server, and substitutes them before script delivery.
- **Fleet secret syntax in PowerShell**: Use `$FLEET_SECRET_GOLAPS_VAULT_TOKEN` inside a single-quoted here-string (`@'...'@`) instead of `$env:FLEET_SECRET_*`. Fleet matches only `$FLEET_SECRET_*` and `${FLEET_SECRET_*}` during upload.
- **Secrets over `stdin` only**: All trigger scripts pass secrets to `golaps --secrets-from-stdin`. On macOS and Linux, the shell trigger scripts read secrets through single-quoted heredocs and pipe them into `/usr/local/bin/golaps --secrets-from-stdin`. On Windows, `run-golaps-windows.ps1` writes the token to `ProcessStartInfo.StandardInput`. Secrets never appear in process arguments or child environments.
- **Binary trust checks**: Before rotation, `run-golaps-macos.sh` and `run-golaps-linux.sh` check that `/usr/local/bin/golaps` and every parent directory are root-owned, not symbolic links, and not writable by group or other. On Windows, `run-golaps-windows.ps1` rejects reparse points and requires owner SID `S-1-5-18` (SYSTEM) or `S-1-5-32-544` (Administrators).
- **Linux package uninstall and host offboarding**: `uninstall-golaps-linux.sh` removes only `/usr/local/bin/golaps`. It keeps the managed administrator account and `/var/lib/golaps` for package updates and reinstalls. When you retire GoLAPS from a Linux host permanently, lock or remove the managed account and remove `/var/lib/golaps`:

```bash
sudo usermod -L example-admin
sudo userdel -r example-admin
sudo rm -rf /var/lib/golaps /var/run/golaps.lock
```
