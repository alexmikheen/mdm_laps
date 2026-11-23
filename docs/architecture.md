# Architecture

GoLAPS rotates a managed local administrator password and stores it in a vault. One rule drives the design: **a rotation is irreversible, and the vault holds the only copy of the new password.** Every ordering choice below follows that rule.

## Safety Ordering (Orchestrator)

`internal/core/orchestr.go` runs each rotation in a strict sequence:

1. **Read the vault record.** If GoLAPS cannot read the vault, the run stops. A vault you cannot read likely blocks writes as well, and rotating without escrow leaves an unknown password on the device.
2. **Stage the new password in the vault before touching the device.** GoLAPS writes the new password to `field_pending_password` (1Password) or `pending_password` (key-value providers). If the final write fails later, the working password remains recoverable. Staging first also checks write access before any OS change.
3. **Rotate the local account password.** GoLAPS tries candidates in priority order (see *Candidate Order*).
4. **Grant and check the Secure Token (macOS).** GoLAPS ensures the managed admin can unlock FileVault.
5. **Commit the rotated password to the vault.** The final write clears the staged field and saves the active password.

If rotation succeeds but the Secure Token grant fails, GoLAPS still commits the password first and then exits non-zero. Without a Secure Token, the account cannot unlock FileVault. Exiting `0` would make MDM report a healthy recovery account when none exists.

### Candidate Order

A leftover staged password means an earlier run stopped between rotating the device and committing to the vault. In that state, the device may already hold the staged value.

GoLAPS checks stored candidates (`pending_password`, `previous_pending_password`, and the current password) and starts rotation with the matching one. It then falls back to the optional legacy password. Account recreation runs only as a last resort, because it costs the Secure Token and triggers a user prompt.

### Policy-Rejected Passwords

The device password policy can refuse the new password (OpenDirectory errors `5402`–`5407`). In that case, the account is healthy, so GoLAPS must not recreate it.

The run reports the failure and clears the staged copy because the device never accepted it. The next run generates a fresh password and retries. The generator also avoids `allowSimple=false` failures by blocking doubled characters and three-character runs.

### Network Failures

GoLAPS tags vault connectivity failures with `[NETWORK]` in the log. No local change is necessary. The run retries on the next MDM check-in after connectivity returns.

## The Go and Swift Contract (macOS)

A small Swift helper (`mac_helper`) runs privileged OpenDirectory and `sysadminctl` actions. Go drives it over JSON on `stdin`. The contract is simple: **the helper reports outcomes, and Go decides policy.**

`change_password` exits with a structured status code:

| Exit | Meaning | Go Decision |
|------|---------|-------------|
| 0 | `ok` | Continue |
| 1 | `od-error` | Report error |
| 2 | `auth-failed` | Try the next candidate, then recreate |
| 3 | `locked` (OD 5305) | Recreate |
| 4 | `reset-refused` | Report error and never treat as success |
| 5 | `policy-rejected` (OD 5402–5407) | Report error, clear staged password, and never recreate |

The helper enforces two strict rules:

- **Detect phantom resets by output, not exit code.** `sysadminctl -resetPasswordFor` can exit `0` while `opendirectoryd` refuses the reset ("Operation is not permitted without secure token unlock"). The helper captures output and treats refusal markers as failure regardless of exit status. Without this check, a phantom reset stores a password the device never accepted.
- **Never administratively reset a Secure Token holder.** Go sets `AllowAdminReset` to `true` only when the account holds no Secure Token. On a token holder, an administrative reset either causes a phantom reset or breaks the SEP and FileVault chain.

GoLAPS sends all secrets over `stdin`, never in `argv`. In the last-resort `dscl` account-creation path, `dscl . -passwd` uses a throwaway value that GoLAPS rotates immediately over `stdin`.

A cross-language contract test parses the Swift enum raw values from `mac_helper.swift` and compares them with the Go constants.

## The Heal Ladder

When the account has no Secure Token or stays locked after every soft fix, Go recreates it:

1. Run `sysadminctl -deleteUser`. macOS protects this command with its last-admin guard.
2. If the guard refuses because the target is the last admin, Go creates a temporary bridge admin (`laps-bridge`) after escrowing its password. Go deletes and recreates the target inside that window, then deletes `laps-bridge` after the target holds a Secure Token.
3. Go checks that the new account exists. If `sysadminctl` exited `0` without creating the record (a create-phantom), Go resets the OpenDirectory cache and retries. As a last resort, Go builds the record with `dscl` so any failure reports a clear reason.

Never run `dscl . -delete` on an account. It bypasses the last-admin guard, orphans the SEP identity, and leaves a tombstone that breaks later `sysadminctl -addUser` calls.

## Secure Token Management

After rotation, `ManageSecureToken` follows cost order:

1. Check whether the target already holds a Secure Token.
2. Try silent grants using vault-known credentials for local token holders (found with `sysadminctl -secureTokenStatus`, not `fdesetup list`).
3. Open the native SwiftUI window (`golaps_auth`) for the console user (see [admin-by-request.md](admin-by-request.md)).

A failed grant fails the run. If a personal recovery key exists locally and MDM holds a bootstrap token, GoLAPS reports `DISABLED (MDM recovery covered)`. That status logs a warning instead of a hard failure because MDM still holds a FileVault recovery path. Coverage changes only the report status: the prompt still runs on the next check-in until the account gets a Secure Token. Both coverage checks fail closed.

## Vault Behavior

- **Retries with jitter.** GoLAPS retries vault writes up to 5 times with linear backoff and random jitter. Jitter stops fleet-wide rollouts from colliding on the same retry schedule.
- **Read-change-write inside the retry.** A timed-out write can still land on the server. Each retry reads the latest item first so stale writes do not cause version conflicts.
- **Duplicate titles resolve to the newest item.** Picking the first match can return an outdated password.
- **Shared run budget.** MDM platforms often kill scripts after 60 minutes. GoLAPS shares one deadline below that limit and reserves time for the final vault write. An idle user prompt cannot push the run past the kill limit before GoLAPS saves the rotated password.

## Capabilities Handshake

`golaps --capabilities` prints a space-separated feature list (`recreate-locked structured-outcome verified-reset last-admin-bridge bt-aware`) before any configuration or vault work. The MDM wrapper script checks these flags instead of comparing version numbers. An older binary prints nothing and exits non-zero, which fails safe.

## Logging

GoLAPS logs to `stdout` for MDM capture and, on macOS, to `/Library/Logs/golaps.log`. Both the wrapper and the binary cap that log at 2000 lines because most MDMs keep only the latest run. GoLAPS scrubs all payload secrets from helper output before it logs any line.
