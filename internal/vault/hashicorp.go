// internal/vault/hashicorp.go
package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hashicorp/vault/api"
)

type HashiCorpClient struct {
	client *api.Client
	path   string
}

func NewHashiCorpClient(address, token, path string) (*HashiCorpClient, error) {
	config := api.DefaultConfig()
	config.Address = address

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	client.SetToken(token)

	// Verify connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = client.Sys().HealthWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to vault: %w", err)
	}

	return &HashiCorpClient{
		client: client,
		path:   path,
	}, nil
}

// readData returns the device's current secret data, or an empty map when the secret does not exist yet.
func (hc *HashiCorpClient) readData(ctx context.Context, deviceID string) (map[string]interface{}, error) {
	secret, err := hc.client.Logical().ReadWithContext(ctx, hc.path+"/"+deviceID)
	if err != nil {
		return nil, err
	}
	if secret == nil || secret.Data == nil {
		return map[string]interface{}{}, nil
	}
	return secret.Data, nil
}

func (hc *HashiCorpClient) GetCredentials(ctx context.Context, deviceID, vaultID, targetAdmin string) (*Credentials, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	res := &Credentials{OldLogin: targetAdmin}

	data, err := hc.readData(ctx, deviceID)
	if err != nil {
		return res, err
	}
	if len(data) == 0 {
		return res, nil
	}
	res.ItemID = hc.path + "/" + deviceID

	if oldLogin, ok := data["login"].(string); ok && oldLogin != "" {
		res.OldLogin = oldLogin
	}
	if oldPassword, ok := data["password"].(string); ok && oldPassword != "" {
		res.OldPassword = oldPassword
	}
	if pending, ok := data["pending_password"].(string); ok && pending != "" {
		res.PendingPassword = pending
	}
	if legacyLogin, ok := data["legacy_login"].(string); ok && legacyLogin != "" {
		res.LegacyLogin = legacyLogin
	}
	if legacyPassword, ok := data["legacy_password"].(string); ok && legacyPassword != "" {
		res.LegacyPassword = legacyPassword
	}

	// Check for migration
	if res.OldLogin != "" && res.OldLogin != targetAdmin {
		res.IsMigration = true
	}

	return res, nil
}

// StagePendingPassword escrows the candidate password before the device is touched. Read-modify-write so the existing record (current password, legacy data) survives the stage.
func (hc *HashiCorpClient) StagePendingPassword(ctx context.Context, creds *Credentials, deviceID, hostname, vaultID, newLogin, newPassword string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	data, err := hc.readData(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("could not read the device secret before staging: %w", err)
	}
	data["hostname"] = hostname
	data["serial"] = deviceID
	data["pending_password"] = newPassword

	if _, err := hc.client.Logical().WriteWithContext(ctx, hc.path+"/"+deviceID, data); err != nil {
		return fmt.Errorf("could not stage the pending password: %w", err)
	}
	creds.ItemID = hc.path + "/" + deviceID
	return nil
}

// ClearPendingPassword drops the staged value after a rotation the device policy refused.
func (hc *HashiCorpClient) ClearPendingPassword(ctx context.Context, creds *Credentials, vaultID string) error {
	if creds.ItemID == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	secret, err := hc.client.Logical().ReadWithContext(ctx, creds.ItemID)
	if err != nil {
		return err
	}
	if secret == nil || secret.Data == nil {
		return nil
	}
	delete(secret.Data, "pending_password")
	_, err = hc.client.Logical().WriteWithContext(ctx, creds.ItemID, secret.Data)
	return err
}

func (hc *HashiCorpClient) UpsertCredentials(ctx context.Context, creds *Credentials, deviceID, hostname, vaultID, newLogin, newPassword, tokenStatus string) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	data := map[string]interface{}{
		"hostname":     hostname,
		"serial":       deviceID,
		"login":        newLogin,
		"password":     newPassword,
		"secure_token": tokenStatus,
		"updated_at":   time.Now().Unix(),
	}
	// The rebuilt map intentionally carries no pending_password: committing the real password IS the confirming write that retires the staged copy.

	// Add legacy credentials if migrating
	if creds.IsMigration && creds.OldLogin != "" {
		data["old_login"] = creds.OldLogin
		data["old_password"] = creds.OldPassword

		// Store in legacy format
		legacyKey := fmt.Sprintf("legacy_%s", creds.OldLogin)
		legacyData := map[string]string{
			"login":    creds.OldLogin,
			"password": creds.OldPassword,
		}
		legacyJSON, _ := json.Marshal(legacyData)
		data[legacyKey] = string(legacyJSON)
	}

	// Write to vault
	_, err := hc.client.Logical().WriteWithContext(ctx, hc.path+"/"+deviceID, data)
	return err
}

// Helper to parse legacy data
func parseLegacyData(value interface{}) (login, password string) {
	switch v := value.(type) {
	case string:
		var data map[string]string
		if err := json.Unmarshal([]byte(v), &data); err == nil {
			login = data["login"]
			password = data["password"]
		}
	case map[string]interface{}:
		if l, ok := v["login"].(string); ok {
			login = l
		}
		if p, ok := v["password"].(string); ok {
			password = p
		}
	}
	return login, password
}

// Ensure interface compliance
var _ Client = (*HashiCorpClient)(nil)
