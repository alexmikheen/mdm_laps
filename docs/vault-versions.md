# Vault SDK Version Compatibility

## Current SDK Versions in `go.mod`

| Provider | SDK Package | Version | Go 1.26+ | Notes |
|----------|-------------|---------|----------|-------|
| 1Password | `github.com/1password/onepassword-sdk-go` | `v0.4.1` | Yes | Uses WASM runtime (`wazero`) |
| HashiCorp Vault | `github.com/hashicorp/vault/api` | `v1.23.0` | Yes | Supports KV v1 and KV v2 |
| AWS Secrets Manager | `github.com/aws/aws-sdk-go-v2/service/secretsmanager` | `v1.21.0` | Yes | Supports `AWS_ENDPOINT_URL` |
| Azure Key Vault | `github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets` | `v0.12.0` | Yes | Uses `azidentity v1.15.0` and `azcore v1.23.3` |
| Bitwarden | `github.com/bitwarden/sdk-go/v2` | `v2.1.0` | Opt-in | Requires `CGO_ENABLED=1 -tags=bitwarden_sdk` |

## Vulnerability Status

Run `govulncheck ./...` after any dependency update to check for known Go vulnerabilities. All packages in `go.mod` currently pass `govulncheck ./...` with zero reported vulnerabilities.

## Notes on Optional Upgrades

- **Azure Key Vault**: `github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets` (`v1.x`) replaces `sdk/keyvault/azsecrets`. Plan that migration in a future release.
- **Bitwarden SDK**: the native static library (`libbitwarden_c.a`) requires CGO and `-tags=bitwarden_sdk`. Default non-CGO builds fail closed for `LAPS_VAULT_TYPE=bitwarden` instead of invoking an external CLI.
