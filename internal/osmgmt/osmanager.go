// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: GPL-3.0-or-later

// internal/osmgmt/manager.go
package osmgmt

import (
	"context"
	"errors"
)

// ErrPolicyRejected marks a rotation whose NEW password was refused by the device's password policy: the staged copy in the vault was provably never applied, so the orchestrator can safely clear it — otherwise the next run tries the refused value as the current password and escalates a healthy account to recreation.
var ErrPolicyRejected = errors.New("the new password was rejected by the device's password policy")

// TokenStatusDisabledPrefix prefixes every ManageSecureToken result meaning the service account still holds no Secure Token, i.e. it cannot unlock FileVault. Callers must treat such a run as a failure: reporting success here is what lets devices end up silently unrecoverable while the MDM job shows "Pass".
const TokenStatusDisabledPrefix = "DISABLED"

// TokenStatusDisabledCovered is the one DISABLED outcome that reports as a warning instead of a failure: the account holds no token, but a personal recovery key exists LOCALLY and the bootstrap token is escrowed. Coverage changes only how the failed grant reports — the GUI prompt still runs on every check-in until the token lands, and the local PRK check cannot prove the MDM actually holds the key, so rollout monitoring should cross-check escrow via the MDM's reporting.
const TokenStatusDisabledCovered = TokenStatusDisabledPrefix + " (MDM recovery covered)"

// Every method takes the run context so the whole process shares one deadline. MDM platforms commonly hard-kill a custom script around 60 minutes; main() sets a deadline below that and every sub-operation derives its own timeout from it. Previously each function built its own context.Background(), so the "budget" the GUI path claimed to respect only started counting when the GUI path began — the vault list, the rotation and the token-holder scan before it were free, and the run could still be hard-killed mid-vault-write.
type Manager interface {
	GetSystemInfo(ctx context.Context) (hostname, serial string)
	// altOldPass is the second authentication candidate (typically the recorded password when the vault's staged pending copy went first). Tried once when oldPass fails to authenticate, BEFORE escalating to recreation — recreation costs the Secure Token and a user prompt.
	EnsureUserAndChangePassword(ctx context.Context, user, oldPass, altOldPass, newPass string) error
	ManageSecureToken(ctx context.Context, targetUser, newPass string, availableCreds map[string]string) string
	DeleteServiceAccountToken(ctx context.Context) error
}
