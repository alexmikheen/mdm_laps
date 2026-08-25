# GoLAPS Project Summary

GoLAPS rotates managed local administrator passwords and stores the latest credentials in a supported secrets backend. The project is designed for MDM deployment on macOS and basic password rotation workflows on Windows.

## Current Capabilities

- macOS and Windows local administrator password rotation.
- Vault token loading from environment variables or macOS System Keychain.
- macOS managed preferences support via the `io.github.golaps` domain.
- Optional legacy password migration through `LEGACY_ADMIN_PASS`.
- Vault client implementations for 1Password, HashiCorp Vault, Bitwarden Secrets Manager, AWS Secrets Manager, and Azure Key Vault.
- Optional Slack, email, and Prometheus integrations.

## Configuration

Use environment variables, an MDM configuration profile, or the provided example files:

```bash
export LAPS_ADMIN_USER="example-admin"
export LAPS_VAULT_TYPE="onepassword"
export LAPS_VAULT_ID="your-vault-id"
export LAPS_VAULT_TOKEN="your-vault-service-token"
export LAPS_PASSWORD_LENGTH=18
```

For macOS MDM profiles, set the following managed preference keys under `io.github.golaps`:

- `AdminUser`
- `VaultID`
- `VaultType`
- `PasswordLength`

The macOS token deployment scripts store the vault token in the System Keychain with the label `GoLAPS_Vault_Token`.

## Repository Notes

- `configs/examples/config.example.env` contains environment variable examples only.
- `configs/examples/laps_config.yaml` is a non-production YAML template.
- `profiles/macos/admin_config.mobileconfig` is a placeholder MDM profile and must be customized before deployment.
- `scripts/mdm/macos/laps_token.sh` is the primary macOS MDM execution script.
- `scripts/mdm/macos/laps_token_minimal.sh` is a minimal token-injection example.

## Public Release Checklist

- Keep only placeholders in config templates and deployment scripts.
- Do not commit `.env` files, production `.mobileconfig` profiles, build artifacts, or real vault IDs.
- Rotate any credentials that were ever committed before publishing.
- Publish from a clean repository or rewrite Git history if old commits contain company names, admin usernames, vault IDs, tokens, or internal URLs.
