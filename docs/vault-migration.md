# GoLAPS Vault Migration Guide

## Supported Vault Providers

GoLAPS supports five secret management providers:

### 1. 1Password Secrets Automation
- **Best for**: Teams that already use 1Password
- **Setup**: Create a service account in 1Password
- **Env vars**: `LAPS_VAULT_TOKEN` or `OP_SERVICE_ACCOUNT_TOKEN`, plus `LAPS_VAULT_ID`

### 2. HashiCorp Vault
- **Best for**: Self-hosted enterprise deployments
- **Setup**: Deploy a Vault server and enable a KV secrets engine
- **Env vars**: `VAULT_ADDR`, `LAPS_VAULT_TOKEN` or `VAULT_TOKEN`, plus `LAPS_VAULT_PATH`

### 3. Bitwarden Secrets Manager
- **Best for**: Teams that use Bitwarden Secrets Manager
- **Setup**: Build with `CGO_ENABLED=1 go build -tags=bitwarden_sdk` and create a machine account token
- **Env vars**: `BWS_ACCESS_TOKEN` (or `LAPS_VAULT_TOKEN`), `LAPS_VAULT_ID` (project ID), optional `BWS_API_URL` and `BWS_IDENTITY_URL`

### 4. AWS Secrets Manager
- **Best for**: AWS infrastructure
- **Setup**: Create an IAM role with Secrets Manager permissions
- **Env vars**: `AWS_REGION`, `AWS_PROFILE` (or IAM role), optional `AWS_ENDPOINT_URL`

### 5. Azure Key Vault
- **Best for**: Microsoft Azure environments
- **Setup**: Create a service principal with Key Vault access
- **Env vars**: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_VAULT_URL`

## The Staged (Pending) Password Field

Every provider stores a **staged password** field next to the current credential (`field_pending_password` in 1Password, `pending_password` in key-value providers). GoLAPS writes the new password there before it rotates the device, then clears it on the final write. See [architecture.md](architecture.md).

When you migrate records between providers, copy this field if it exists. It may hold the active password on the device.

## Migration Steps

### From 1Password to HashiCorp Vault

1. Export records from 1Password.
2. Enable the HashiCorp Vault KV engine:
   ```bash
   vault secrets enable -path=secret kv-v2
   ```
3. Update environment variables:
   ```bash
   export LAPS_VAULT_TYPE="hashicorp"
   export VAULT_ADDR="https://vault.example.com:8200"
   export LAPS_VAULT_TOKEN="your-vault-token"
   export LAPS_VAULT_PATH="secret/data/laps"
   ```

### From Any Provider to AWS Secrets Manager

1. Create an IAM policy:
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "secretsmanager:GetSecretValue",
      "secretsmanager:CreateSecret",
      "secretsmanager:UpdateSecret"
    ],
    "Resource": "arn:aws:secretsmanager:*:*:secret:laps/*"
  }]
}
```

2. Update environment variables:
   ```bash
   export LAPS_VAULT_TYPE="aws"
   export AWS_REGION="us-east-1"
   ```

## Configuration Examples

See `configs/examples/config.example.env` and `configs/examples/laps_config.yaml` for full examples.

## Test Your Configuration

```bash
printf '%s\n\n' "$LAPS_VAULT_TOKEN" | sudo /usr/local/bin/golaps --secrets-from-stdin
```
