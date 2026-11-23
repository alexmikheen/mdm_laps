// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

package vault

import "context"

const (
	PendingPasswordFieldID = "field_pending_password"
	PreviousPendingFieldID = "field_previous_pending"
	BridgePasswordFieldID  = "field_bridge_password"
)

type Credentials struct {
	ItemID      string
	OldLogin    string
	OldPassword string
	// PendingPassword holds a staged candidate from an incomplete run.
	PendingPassword string
	// PreviousPendingPassword holds the pending value displaced by the latest stage.
	PreviousPendingPassword string
	// BridgePassword holds the temporary bridge admin password when a bridge exists.
	BridgePassword string
	LegacyLogin    string
	LegacyPassword string
	IsMigration    bool
}

func (creds *Credentials) recordConfirmed(login, password string) {
	if creds.IsMigration {
		creds.LegacyLogin = creds.OldLogin
		creds.LegacyPassword = creds.OldPassword
		creds.IsMigration = false
	}
	creds.OldLogin = login
	creds.OldPassword = password
	creds.PendingPassword = ""
	creds.PreviousPendingPassword = ""
}

type Client interface {
	GetCredentials(ctx context.Context, deviceID, vaultID, targetAdmin string) (*Credentials, error)

	// StagePendingPassword stores the candidate password before the OS rotation and updates creds.ItemID.
	StagePendingPassword(ctx context.Context, creds *Credentials, deviceID, hostname, vaultID, newLogin, newPassword string) error

	// ConfirmLivePassword promotes a device-verified candidate to the active password and clears pending fields.
	ConfirmLivePassword(ctx context.Context, creds *Credentials, deviceID, hostname, vaultID, login, live string) error

	UpsertCredentials(ctx context.Context, creds *Credentials, deviceID, hostname, vaultID, newLogin, newPassword, tokenStatus string) error

	// ClearPendingPassword removes the staged password and restores any previous pending value.
	ClearPendingPassword(ctx context.Context, creds *Credentials, vaultID string) error

	// StageBridgePassword stores the bridge admin password before GoLAPS creates the bridge account.
	StageBridgePassword(ctx context.Context, creds *Credentials, vaultID, password string) error

	ClearBridgePassword(ctx context.Context, creds *Credentials, vaultID string) error
}
