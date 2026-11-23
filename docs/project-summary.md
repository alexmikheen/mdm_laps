# GoLAPS Project Summary

GoLAPS rotates managed local administrator passwords and stores the latest credential in a supported vault provider. You can deploy it through MDM on macOS or run it on Windows.

## Current Capabilities

- Local administrator password rotation on macOS and Windows.
- Secret delivery through `--secrets-from-stdin`, environment variables, or the macOS System Keychain.
- macOS managed preferences support under the `io.github.golaps` domain.
- Optional legacy password migration through `LEGACY_ADMIN_PASS`.
- Vault clients for 1Password, HashiCorp Vault, Bitwarden Secrets Manager, AWS Secrets Manager, and Azure Key Vault.
- Optional Slack, email, and Prometheus integrations.

## Configuration

Use environment variables, an MDM configuration profile, or the example files:

```bash
export LAPS_ADMIN_USER="example-admin"
export LAPS_VAULT_TYPE="onepassword"
export LAPS_VAULT_ID="your-vault-id"
export LAPS_VAULT_TOKEN="your-vault-service-token"
export LAPS_PASSWORD_LENGTH=18
```

For macOS MDM profiles, set these managed preference keys under `io.github.golaps`:

- `AdminUser`
- `VaultID`
- `VaultType`
- `PasswordLength`

The macOS MDM trigger scripts pass the vault token to GoLAPS over `stdin` (`--secrets-from-stdin`). They also delete any leftover `GoLAPS_Vault_Token` entry from the System Keychain.

## Repository Notes

- `configs/examples/config.example.env` contains environment variable examples only.
- `configs/examples/laps_config.yaml` is a non-production YAML template.
- `profiles/macos/admin_config.mobileconfig` is a placeholder MDM profile. Customize it before deployment.
- `scripts/mdm/macos/laps_token.sh` is the primary macOS MDM trigger script.
- `scripts/mdm/macos/laps_token_minimal.sh` is a minimal token-delivery example.

## Public Release Checklist

- Keep only placeholders in configuration templates and deployment scripts.
- Do not commit `.env` files, production `.mobileconfig` profiles, build artifacts, or real vault IDs.
- Rotate any credentials that appeared in earlier commits before you publish.
- Publish from a clean repository if old commits contain company names, admin usernames, vault IDs, tokens, or internal URLs.
