// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

package osmgmt

import (
	"context"
	"errors"
)

// ErrPolicyRejected signals that the device password policy refused the new password.
var ErrPolicyRejected = errors.New("the new password was rejected by the device's password policy")

const (
	TokenStatusDisabledPrefix        = "DISABLED"
	// TokenStatusDisabledCovered reports no Secure Token while a local PRK and escrowed bootstrap token exist.
	TokenStatusDisabledCovered       = TokenStatusDisabledPrefix + " (MDM recovery covered)"
	TokenStatusDisabledWrongPassword = TokenStatusDisabledPrefix + " (wrong password streak)"
	TokenStatusDisabledWindowKilled  = TokenStatusDisabledPrefix + " (window ended early)"
	// TokenStatusDisabledDeadlock reports that only laps-bridge holds a Secure Token and no stored password fits it.
	TokenStatusDisabledDeadlock      = TokenStatusDisabledPrefix + " (bridge deadlock)"
)

// ErrSkipRun ends a preflight check cleanly with exit code 0.
var ErrSkipRun = errors.New("run skipped by preflight")

// ErrConflict stops the run when another process locks the account or repeats account recreation.
var ErrConflict = errors.New("[CONFLICT]")

// ErrNoTokenHolder stops account recreation when no local account holds a Secure Token.
var ErrNoTokenHolder = errors.New("[NO TOKEN HOLDER]")

const LegacyBridgeAdmin = "laps-bridge"

// BridgeEscrow stores the bridge admin password in the vault before GoLAPS creates the account.
type BridgeEscrow func(ctx context.Context, password string) error

type Manager interface {
	// Preflight runs safety checks and soft account repairs before GoLAPS accesses the vault.
	Preflight(ctx context.Context, user, probeURL string) error
	GetSystemInfo(ctx context.Context) (hostname, serial string, err error)
	EnsureUserAndChangePassword(ctx context.Context, user string, candidates []string, newPass string) error
	// VerifyPassword checks whether pass is the live password of user, or returns errors.ErrUnsupported.
	VerifyPassword(ctx context.Context, user, pass string) (ok bool, err error)
	ManageSecureToken(ctx context.Context, targetUser, newPass string, availableCreds map[string]string) string
	// CleanupLegacyAdmin deletes laps-bridge once targetUser holds a Secure Token and returns true if absent.
	CleanupLegacyAdmin(ctx context.Context, targetUser string) (absent bool)
	SetBridgeEscrow(escrow BridgeEscrow)
	DeleteServiceAccountToken(ctx context.Context) error
}
