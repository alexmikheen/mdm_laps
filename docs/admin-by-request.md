# Admin By Request Integration

The interactive token-grant path in GoLAPS supports [Admin By Request](https://www.adminbyrequest.com) (AbR). AbR removes standing local administrator rights and grants them per session.

GoLAPS does not require AbR. On Macs without AbR, the GUI prompt works directly. On AbR-managed fleets, the prompt fails without extra handling.

## The Problem

Granting a Secure Token requires an administrator credential. `opendirectoryd` refuses the grant with error `5101` ("Credential is not an admin") when the user is not in the local `admin` group.

AbR demotes human users by design. On an AbR-managed Mac, the console user types a valid password, but the grant still fails without an active admin session.

## What GoLAPS Does

1. **Check admin membership before the password step.** GoLAPS checks whether the console user belongs to the `admin` group (`dsmemberutil checkmembership`). If not, and AbR is present, the window starts on the administrator-access step first.
2. **Open AbR in the console user session.** The `adminbyrequest://` URL scheme only activates the app and does not show the elevation prompt. Running `open -a "Admin By Request"` opens that prompt. GoLAPS runs `launchctl asuser <uid> sudo -u <user> open -a "Admin By Request"`. Both parts are necessary: `asuser` alone stays root, and `sudo -u` alone stays outside the GUI session.
3. **Poll for approval.** `dseditgroup` membership checks run locally and return fast. GoLAPS polls every 2 seconds and continues shortly after AbR approves the request. The wait ends after the prompt timeout so an unanswered prompt cannot block the MDM script slot. The grant retries on the next check-in.
4. **Handle mid-flow expiry.** An AbR session can expire between the pre-check and the grant. If the grant fails and the user is no longer in the `admin` group, GoLAPS returns to the AbR step and retries the already-checked password once.
5. **Restore service-admin membership on every run.** AbR cleanup demotes admins that are not in its exclusion list. A demoted service admin rotates cleanly, but it cannot recover the Mac. GoLAPS preflight adds the managed admin back to the `admin` group on every run and logs a warning. Add the managed admin to AbR **ExcludedAccounts** for a permanent fix.

On Windows, the account-management PowerShell script also checks and restores Administrators group membership by SID (`S-1-5-32-544`) on every run.

## Native Auth Window

GoLAPS uses the native SwiftUI and AppKit binary `/usr/local/bin/golaps_auth` in the console user session instead of `osascript`. GoLAPS compiles all prompt text and optional help links into `auth_window.swift` so external callers cannot inject text. If `helpArticle` is empty, the window omits the help button.
