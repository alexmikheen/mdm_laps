# GoLAPS Vault Migration Guide

## Supported Vault Providers

GoLAPS supports the following secret management systems:

### 1. 1Password Secrets Automation
- **Best for**: Teams already using 1Password
- **Setup**: Create a service account in 1Password
- **Env vars**: `LAPS_VAULT_TOKEN` or `OP_SERVICE_ACCOUNT_TOKEN`, plus `LAPS_VAULT_ID`

### 2. HashiCorp Vault
- **Best for**: Self-hosted enterprise deployments
- **Setup**: Deploy Vault server, create KV secrets engine
- **Env vars**: `VAULT_ADDR`, `LAPS_VAULT_TOKEN` or `VAULT_TOKEN`, plus `LAPS_VAULT_PATH`

### 3. Bitwarden Secrets Manager
- **Best for**: Open-source focused organizations
- **Setup**: Create API key in Bitwarden organization
- **Env vars**: `BW_SERVER_URL`, `BW_API_KEY`, `BW_ORG_ID`

### 4. AWS Secrets Manager
- **Best for**: AWS-centric infrastructure
- **Setup**: IAM role with Secrets Manager permissions
- **Env vars**: `AWS_REGION`, `AWS_PROFILE` (or IAM role)

### 5. Azure Key Vault
- **Best for**: Microsoft/Azure environments, macOS fleets in Azure AD
- **Setup**: Service principal with Key Vault access
- **Env vars**: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_VAULT_URL`

## The staged (pending) password field

Every provider stores, next to the current credential, a **staged password** field
(`field_pending_password` in 1Password, `pending_password` in the key/value providers). GoLAPS
writes the new password there *before* rotating the device and drops it on the confirming write —
see [architecture.md](architecture.md). When migrating records between providers, carry this field
over if it is present: it may be the password the device actually holds.

## Migration Steps

### From 1Password to HashiCorp Vault

1. Export data from 1Password
2. Set up HashiCorp Vault KV engine:
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

1. Create IAM policy:
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

2. Update environment:
   ```bash
   export LAPS_VAULT_TYPE="aws"
   export AWS_REGION="us-east-1"
   ```

## Configuration Examples

See `configs/examples/config.example.env` and `configs/examples/laps_config.yaml` for complete examples.

## Testing Your Configuration

```bash
# Test connection
./golaps
```
