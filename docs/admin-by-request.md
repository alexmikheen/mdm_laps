# Admin By Request integration

GoLAPS's interactive token-grant path is aware of [Admin By Request](https://www.adminbyrequest.com)
(AbR), a privilege-management tool that removes standing local admin rights and hands them back per
session. Nothing in GoLAPS *requires* AbR — on Macs without it the GUI prompt works as-is — but on
AbR-managed fleets the prompt would otherwise be a dead end, and this page explains why and what
GoLAPS does about it.

## The problem

Granting a Secure Token needs an *administrator's* credential: opendirectoryd refuses the grant
with error 5101 ("Credential is not an admin") when the authenticating user is not in the local
admin group. AbR demotes human users by design, so on an AbR-managed Mac the console user's
password is **correct and still cannot succeed**. Without special handling the user types their
valid password, gets a generic "unexpected system error", and files a ticket.

## What GoLAPS does

1. **Pre-check before asking for the password.** If the console user is not an admin member
   (`dsmemberutil checkmembership`) and AbR is installed, GoLAPS walks the user through obtaining a
   temporary admin session *first*, instead of collecting a password that cannot work.
2. **Raise AbR the way that actually works.** The `adminbyrequest://` URL scheme only activates the
   app — it carries no verbs and does not surface the "start an administrator session?" prompt.
   Re-launching the single-instance app with `open -a "Admin By Request"` does. GoLAPS drives the
   app by name, in the user's Aqua session, as the user (`launchctl asuser <uid> sudo -u <user>
   open -a ...` — both halves are required: `asuser` alone keeps the process root and resolves the
   wrong user's preferences; `sudo -u` alone never enters the GUI session).
3. **Poll for the approval.** `dseditgroup`/`dsmemberutil` membership checks are instant local
   lookups, so GoLAPS polls every 2 seconds and continues within ~2s of the AbR approval landing.
   The wait is capped (15 minutes) so a prompt nobody saw cannot park the device's MDM script slot
   for the better part of an hour — the whole grant simply retries on the next check-in.
4. **Handle mid-flow expiry.** An AbR session can expire between the pre-check and the grant. If
   the grant is refused *and* the user is no longer an admin member, GoLAPS re-offers the AbR flow
   and retries the same already-validated password once, instead of failing with a generic error.
5. **Re-assert the service admin's membership every run.** AbR's rights cleanup demotes admins that
   are not in its exclusion list, and a demoted service admin rotates green while being useless for
   recovery. The MDM wrapper script re-adds the managed admin to the admin group on every run and
   logs a warning when that keeps recurring — the durable fix is adding the account to AbR's
   **ExcludedAccounts**.

The same idea appears on Windows: the account-management PowerShell re-asserts membership in the
Administrators group by SID (`S-1-5-32-544`) on every run, for the same reason.

## Dialogs

All user-facing dialogs are native AppleScript dialogs run in the console user's session. They
carry an optional **Open Help** button when the `LAPS_SUPPORT_URL` environment variable is set
(point it at your IT portal or the rollout announcement); without it the dialogs simply omit the
button. The help URL opens in the user's real default browser with their existing sessions, using
the same `asuser` + `sudo -u` pairing described above.
