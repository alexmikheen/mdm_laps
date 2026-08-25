# Configuration

GoLAPS can be configured with environment variables and, on macOS, managed preferences under the `io.github.golaps` domain.

## Common Settings

```bash
export LAPS_ADMIN_USER="example-admin"
export LAPS_VAULT_TYPE="onepassword"
export LAPS_VAULT_ID="your-vault-id"
export LAPS_PASSWORD_LENGTH=18
```

Supported `LAPS_VAULT_TYPE` values:

- `onepassword`
- `hashicorp`
- `bitwarden`
- `aws`
- `azure`

`LAPS_VAULT_TOKEN` is a generic token alias for providers that authenticate with a single token. Provider-specific variables still work.

Optional settings:

```bash
# Help link offered by the macOS GUI dialogs (IT portal / rollout announcement).
# When unset, the dialogs simply omit their help button.
export LAPS_SUPPORT_URL="https://support.example.com/laps"

# Password of a legacy admin account from a previous deployment, used as the
# last-resort rotation candidate during migration.
export LEGACY_ADMIN_PASS="previous-admin-password"
```

On macOS, runs are also logged to `/Library/Logs/golaps.log` (tail-capped at 2000 lines). Most MDMs
keep only the latest run per device, so this local file is the only run history that survives.

## 1Password

```bash
export LAPS_VAULT_TYPE="onepassword"
export LAPS_VAULT_TOKEN="your-service-account-token"
```

Alternative:

```bash
export OP_SERVICE_ACCOUNT_TOKEN="your-service-account-token"
```

On macOS, the token can also be stored in the System Keychain with the label `GoLAPS_Vault_Token`.

## HashiCorp Vault

```bash
export LAPS_VAULT_TYPE="hashicorp"
export VAULT_ADDR="https://vault.example.com:8200"
export LAPS_VAULT_TOKEN="your-vault-token"
export LAPS_VAULT_PATH="secret/data/laps"
```

Alternative:

```bash
export VAULT_TOKEN="your-vault-token"
```

## Bitwarden Secrets Manager

```bash
export LAPS_VAULT_TYPE="bitwarden"
export BW_SERVER_URL="https://api.bitwarden.com"
export BW_API_KEY="client_id:client_secret"
export BW_ORG_ID="your-organization-id"
```

## AWS Secrets Manager

```bash
export LAPS_VAULT_TYPE="aws"
export AWS_REGION="us-east-1"
export AWS_PROFILE="default"
```

AWS credentials are loaded through the default AWS SDK credential chain.

## Azure Key Vault

```bash
export LAPS_VAULT_TYPE="azure"
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"
export AZURE_VAULT_URL="https://your-vault.vault.azure.net"
```

## macOS Managed Preferences

Set these keys under `io.github.golaps`:

- `AdminUser`
- `VaultID`
- `VaultType`
- `PasswordLength`

See [profiles/macos/admin_config.mobileconfig](../profiles/macos/admin_config.mobileconfig) for a placeholder profile.
