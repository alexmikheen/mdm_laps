// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
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

// isKVv2 reports whether the configured path targets a Vault KV v2 mount (e.g. "secret/data/laps").
func (hc *HashiCorpClient) isKVv2() bool {
	return strings.Contains(hc.path, "/data/") || strings.HasSuffix(hc.path, "/data")
}

// readData returns the device's current secret data, or an empty map when the secret does not exist yet.
func (hc *HashiCorpClient) readData(ctx context.Context, deviceID string) (map[string]interface{}, error) {
	return hc.readDataAt(ctx, hc.path+"/"+deviceID)
}

func (hc *HashiCorpClient) readDataAt(ctx context.Context, fullPath string) (map[string]interface{}, error) {
	secret, err := hc.client.Logical().ReadWithContext(ctx, fullPath)
	if err != nil {
		return nil, err
	}
	if secret == nil || secret.Data == nil {
		return map[string]interface{}{}, nil
	}
	if hc.isKVv2() {
		if inner, ok := secret.Data["data"].(map[string]interface{}); ok && inner != nil {
			return inner, nil
		}
		return map[string]interface{}{}, nil
	}
	return secret.Data, nil
}

func (hc *HashiCorpClient) writeDataAt(ctx context.Context, fullPath string, data map[string]interface{}) error {
	payload := data
	if hc.isKVv2() {
		payload = map[string]interface{}{"data": data}
	}
	_, err := hc.client.Logical().WriteWithContext(ctx, fullPath, payload)
	return err
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
	if prevPending, ok := data["previous_pending_password"].(string); ok && prevPending != "" {
		res.PreviousPendingPassword = prevPending
	}
	if bridgePass, ok := data["bridge_password"].(string); ok && bridgePass != "" {
		res.BridgePassword = bridgePass
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

// StagePendingPassword stores the candidate before OS rotation and preserves existing fields.
func (hc *HashiCorpClient) StagePendingPassword(ctx context.Context, creds *Credentials, deviceID, hostname, vaultID, newLogin, newPassword string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	data, err := hc.readData(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("could not read the device secret before staging: %w", err)
	}
	data["hostname"] = hostname
	data["serial"] = deviceID
	if old, ok := data["pending_password"].(string); ok && old != "" && old != newPassword {
		data["previous_pending_password"] = old
	}
	data["pending_password"] = newPassword

	if err := hc.writeDataAt(ctx, hc.path+"/"+deviceID, data); err != nil {
		return fmt.Errorf("could not stage the pending password: %w", err)
	}
	creds.ItemID = hc.path + "/" + deviceID
	return nil
}

// ClearPendingPassword removes the staged value after a policy-rejected rotation.
func (hc *HashiCorpClient) ClearPendingPassword(ctx context.Context, creds *Credentials, vaultID string) error {
	if creds.ItemID == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	data, err := hc.readDataAt(ctx, creds.ItemID)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	delete(data, "pending_password")
	if prev, ok := data["previous_pending_password"].(string); ok && prev != "" {
		data["pending_password"] = prev
		delete(data, "previous_pending_password")
	}
	return hc.writeDataAt(ctx, creds.ItemID, data)
}

func (hc *HashiCorpClient) ConfirmLivePassword(ctx context.Context, creds *Credentials, deviceID, hostname, vaultID, login, live string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	data, err := hc.readData(ctx, deviceID)
	if err != nil {
		return err
	}
	if creds.IsMigration && creds.OldLogin != "" {
		if existing, _ := data["legacy_login"].(string); existing == "" {
			data["legacy_login"] = creds.OldLogin
			data["legacy_password"] = creds.OldPassword
		}
	}
	data["hostname"] = hostname
	data["serial"] = deviceID
	data["login"] = login
	data["password"] = live
	delete(data, "pending_password")
	delete(data, "previous_pending_password")
	if err := hc.writeDataAt(ctx, hc.path+"/"+deviceID, data); err != nil {
		return err
	}
	creds.recordConfirmed(login, live)
	return nil
}

func (hc *HashiCorpClient) StageBridgePassword(ctx context.Context, creds *Credentials, vaultID, password string) error {
	if creds.ItemID == "" {
		return fmt.Errorf("device has no vault record yet; cannot escrow bridge password")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	data, err := hc.readDataAt(ctx, creds.ItemID)
	if err != nil {
		return err
	}
	data["bridge_password"] = password
	if err := hc.writeDataAt(ctx, creds.ItemID, data); err != nil {
		return err
	}
	creds.BridgePassword = password
	return nil
}

func (hc *HashiCorpClient) ClearBridgePassword(ctx context.Context, creds *Credentials, vaultID string) error {
	if creds.ItemID == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	data, err := hc.readDataAt(ctx, creds.ItemID)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		creds.BridgePassword = ""
		return nil
	}
	delete(data, "bridge_password")
	if err := hc.writeDataAt(ctx, creds.ItemID, data); err != nil {
		return err
	}
	creds.BridgePassword = ""
	return nil
}

func (hc *HashiCorpClient) UpsertCredentials(ctx context.Context, creds *Credentials, deviceID, hostname, vaultID, newLogin, newPassword, tokenStatus string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Read-modify-write so bridge_password and existing legacy_* fields survive until explicitly cleared.
	data, err := hc.readData(ctx, deviceID)
	if err != nil {
		return err
	}
	if creds.IsMigration && creds.OldLogin != "" {
		if existing, _ := data["legacy_login"].(string); existing == "" {
			data["legacy_login"] = creds.OldLogin
			data["legacy_password"] = creds.OldPassword
		}
	}
	data["hostname"] = hostname
	data["serial"] = deviceID
	data["login"] = newLogin
	data["password"] = newPassword
	data["secure_token"] = tokenStatus
	data["updated_at"] = time.Now().Unix()
	delete(data, "pending_password")
	delete(data, "previous_pending_password")

	return hc.writeDataAt(ctx, hc.path+"/"+deviceID, data)
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
