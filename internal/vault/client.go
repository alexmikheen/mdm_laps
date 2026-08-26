// internal/vault/client.go
package vault

import "context"

// PendingPasswordFieldID holds a password that has been generated but not yet confirmed applied to the device. See Client.StagePendingPassword.
const PendingPasswordFieldID = "field_pending_password"

type Credentials struct {
	ItemID      string
	OldLogin    string
	OldPassword string
	// PendingPassword is a staged password left behind by a run that did not reach its confirming write. It may or may not be the one the device actually holds — treat it as a recovery candidate, never as the known-good password.
	PendingPassword string
	LegacyLogin     string
	LegacyPassword  string
	IsMigration     bool
}

type Client interface {
	GetCredentials(ctx context.Context, deviceID, vaultID, targetAdmin string) (*Credentials, error)

	// StagePendingPassword escrows the candidate password BEFORE it is applied to the device, and records the resulting item ID in creds. Rotation is irreversible and the vault is the only copy: if the vault write is attempted only after the OS password has changed and that write fails, the working password is gone and the account is unreachable. Staging first also proves the service account still has write access before anything irreversible happens. UpsertCredentials clears the staged field once the real password is committed. A backend that cannot stage must return an error here — never a silent no-op — so the orchestrator aborts before touching the device.
	StagePendingPassword(ctx context.Context, creds *Credentials, deviceID, hostname, vaultID, newLogin, newPassword string) error

	UpsertCredentials(ctx context.Context, creds *Credentials, deviceID, hostname, vaultID, newLogin, newPassword, tokenStatus string) error

	// ClearPendingPassword removes the staged field from the item. Only safe when the staged password provably never reached the device (a policy-rejected rotation): leaving it would make the next run try a known-refused password as the current one.
	ClearPendingPassword(ctx context.Context, creds *Credentials, vaultID string) error
}
