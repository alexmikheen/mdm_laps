# Configuration

You can configure GoLAPS with environment variables and, on macOS, managed preferences under the `io.github.golaps` domain.

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

`LAPS_VAULT_TOKEN` is a generic token alias for single-token providers. Provider-specific variables still work.

For MDM deployments, pass secrets over `stdin` with `--secrets-from-stdin` (line 1: vault token, line 2: optional `LEGACY_ADMIN_PASS`). That keeps secrets out of `ps` and process environments.

Optional migration setting:

```bash
# Password of a legacy admin account from a previous deployment, used as the last-resort rotation candidate during migration.
export LEGACY_ADMIN_PASS="previous-admin-password"
```

On macOS, GoLAPS also logs runs to `/Library/Logs/golaps.log` and caps the file at 2000 lines. Most MDMs keep only the latest run per device, so this local file preserves run history.

## 1Password

```bash
export LAPS_VAULT_TYPE="onepassword"
export LAPS_VAULT_TOKEN="your-service-account-token"
```

Alternative variable:

```bash
export OP_SERVICE_ACCOUNT_TOKEN="your-service-account-token"
```

On macOS, GoLAPS can also read the token from the System Keychain under the label `GoLAPS_Vault_Token` and then delete it.

## HashiCorp Vault

```bash
export LAPS_VAULT_TYPE="hashicorp"
export VAULT_ADDR="https://vault.example.com:8200"
export LAPS_VAULT_TOKEN="your-vault-token"
export LAPS_VAULT_PATH="secret/data/laps"
```

Alternative variable:

```bash
export VAULT_TOKEN="your-vault-token"
```

## Bitwarden Secrets Manager

Build GoLAPS with CGO and the `bitwarden_sdk` build tag (`CGO_ENABLED=1 go build -tags=bitwarden_sdk`), then set:

```bash
export LAPS_VAULT_TYPE="bitwarden"
export BWS_ACCESS_TOKEN="your-machine-account-token"
export LAPS_VAULT_ID="your-bitwarden-project-id"
# Optional for self-hosted Bitwarden instances:
export BWS_API_URL="https://api.bitwarden.com"
export BWS_IDENTITY_URL="https://identity.bitwarden.com"
```

## AWS Secrets Manager

```bash
export LAPS_VAULT_TYPE="aws"
export AWS_REGION="us-east-1"
export AWS_PROFILE="default"
# Optional for VPC endpoints, LocalStack, or Moto:
export AWS_ENDPOINT_URL="https://secretsmanager.example.internal"
```

GoLAPS loads AWS credentials through the default AWS SDK v2 credential chain.

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
