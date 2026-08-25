# Architecture

GoLAPS rotates a managed local administrator password and escrows it to a vault. The design is
shaped by one constraint: **a rotation is irreversible, and the vault holds the only copy of the
result.** Every ordering decision below follows from that.

## Safety ordering (the orchestrator)

`internal/core/orchestr.go` runs one rotation as a strict sequence:

1. **Read the vault record.** If it cannot be read, the run aborts — a vault we cannot read is
   very likely a vault we cannot write, and rotating without a reliable escrow is how a device
   ends up with a password nobody knows.
2. **Stage the new password in the vault BEFORE touching the device** (`field_pending_password` /
   `pending_password`). If the device is rotated first and the confirming write fails, the working
   password is gone. Staging first also proves the service account still has write access before
   anything irreversible happens.
3. **Rotate,** starting with the best candidate (see *Candidate order* below).
4. **Grant / verify the Secure Token** (macOS; see below).
5. **Commit the rotated password** to the vault. The confirming write drops the staged copy —
   committing the real password *is* the retirement of the pending field.

A run whose rotation succeeded but whose token grant failed still commits the password (step 5
comes first), then exits non-zero: without a Secure Token the account cannot unlock FileVault, and
exiting 0 is what makes an MDM report "Pass" for devices with no working recovery account.

### Candidate order

A staged password surviving from an earlier run means that run died *between* rotating the device
and confirming the vault — and in every observed failure of that kind the device already held the
staged value. So the rotation starts with the pending password, keeps the recorded password as the
alternate candidate (one extra helper call), and only then falls back to the optional legacy
password. Recreation is the last resort: it costs the Secure Token and a user prompt.

### Policy-rejected passwords

If the device's password policy refuses the *new* password (OpenDirectory 5402–5407: quality,
length, character classes, change-too-soon), the account is healthy and recreation would destroy a
working admin over a dice roll. The run reports the failure, **clears the staged copy** (it
provably never reached the device — leaving it would make the next run try a known-refused value
as the current password), and the next run retries with a fresh password. The generator also
avoids the common `allowSimple=false` traps up front: no doubled characters, no three-character
ascending/descending runs.

### Network failures

Connectivity failures to the vault are tagged with a `[NETWORK]` marker in the log. There is
nothing to fix on the device — the run simply retries on the next MDM check-in once connectivity
returns.

## The Go ↔ Swift contract (macOS)

The privileged OpenDirectory work lives in a small Swift helper (`mac_helper`), driven by JSON on
stdin. The contract is: **the helper reports, Go decides.**

`change_password` exits with a structured outcome:

| Exit | Meaning | Go's decision |
|------|---------|---------------|
| 0 | ok | continue |
| 1 | od-error | report |
| 2 | auth-failed | try the alternate candidate, then recreate |
| 3 | locked (OD 5305) | recreate |
| 4 | reset-refused | report — never claimed as success |
| 5 | policy-rejected (OD 5402–5407) | report + clear the staged password; **never** recreate |

Two hard-won rules are encoded in the helper:

- **Phantom resets are detected by output, not exit code.** `sysadminctl -resetPasswordFor` can
  exit 0 while opendirectoryd refuses the reset ("Operation is not permitted without secure token
  unlock"). The helper captures the process output and treats the refusal markers as failure
  regardless of the exit status. This is the single most important behavior in the project: a
  phantom reset escrows a password the device never received, silently desynchronizing the device
  from the vault while every run shows green.
- **Token holders are never administratively reset.** `AllowAdminReset` is true only for an
  account that provably holds no Secure Token (e.g. one created seconds ago). On a token holder an
  administrative reset either phantoms (above) or succeeds while breaking the SEP/FileVault chain —
  the token still shows ENABLED but no longer unlocks the volume at preboot.

All secrets travel over stdin — never in argv. The one place a password must appear in an argument
list (`dscl . -passwd` during the last-resort account build) uses a throwaway value that is rotated
to the real password over stdin immediately afterwards.

A cross-language contract test parses the Swift enum's raw values out of `mac_helper.swift` and
compares them with the Go constants, so the two sides cannot drift silently.

## The heal ladder

When the account is unusable (no token, or locked beyond every soft repair), Go recreates it:

1. `sysadminctl -deleteUser` — the supported path, protected by macOS's last-admin guard.
2. If the guard refuses (the target is the last admin — common where a privilege-management tool
   demotes human admins), a **temporary bridge admin** (`laps-bridge`) is created to hold the admin
   count, the target is deleted and recreated *inside* the bridge window, and the bridge is retired
   once the target holds a Secure Token. The bridge never needs a token — the guard counts admins.
3. Account creation is verified afterwards; a "create-phantom" (sysadminctl exits 0, account does
   not exist) is retried through an OpenDirectory cache reset, and as a last resort the record is
   assembled directly via `dscl` — a path that at least fails loudly and names the reason.

Never `dscl . -delete` an account directly: it bypasses the last-admin guard, orphans the SEP
identity, and leaves a tombstone that makes every later `sysadminctl -addUser` for that name exit 0
without creating anything.

## Secure Token management

After rotation, `ManageSecureToken` works through candidates in cost order: verify the token is
already present → silent grants using every vault-known credential of every actual token holder
(enumerated via per-account `sysadminctl -secureTokenStatus`, *not* `fdesetup list`, which reports
FileVault-enabled users — a different set) → the interactive GUI prompt (see
[admin-by-request.md](admin-by-request.md)).

A failed grant is a failed run. The one softening: if a personal recovery key exists locally
**and** the bootstrap token is escrowed, the failure reports as `DISABLED (MDM recovery covered)` —
a warning, not a red status — because the MDM still has a FileVault recovery path. Coverage changes
only how the failure *reports*: the prompt runs again on every check-in until the token lands, and
a token-less service admin is never an accepted end state. Both coverage probes fail closed.

## Vault behavior

- **Retries with jitter.** Vault writes are retried (5 attempts, linear backoff plus random
  jitter). The jitter matters at fleet scale: a synchronized rollout makes hundreds of devices
  collide on the same backoff grid and conflict again on every retry.
- **Read-modify-write inside the retry.** A timed-out write can still land server-side; re-sending
  the same stale item then fails every remaining attempt with a version conflict. Each attempt
  re-reads the item first.
- **Duplicate titles resolve to the newest item.** Taking the first match can hand back a
  months-old password.
- **The run budget.** MDM platforms commonly hard-kill a custom script around 60 minutes. The whole
  run shares one deadline set below that, and every user-facing dialog reserves a slice of the
  budget for the final vault write, so a human staring at a prompt can never push the run past the
  kill limit with the rotated password unrecorded.

## Capabilities handshake

`golaps --capabilities` prints a space-separated feature list
(`recreate-locked structured-outcome verified-reset last-admin-bridge bt-aware`) before any
config/vault/keychain work. The MDM wrapper script gates its handover on the flags it needs instead
of comparing version numbers — an older binary prints nothing and exits non-zero, which reads as
"cannot", the safe direction.

## Logging

Runs log to stdout (the MDM captures it) and, on macOS, to `/Library/Logs/golaps.log` — tail-capped
at 2000 lines by both the wrapper and the binary. Most MDMs keep only the latest run per device, so
the local file is the only run history that survives. Helper output is scrubbed against every
secret the payload carried before it is logged.
