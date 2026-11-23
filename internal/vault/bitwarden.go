// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"
)

type bwSecret struct {
	ID    string
	Key   string
	Value string
	Note  string
}

type bwSecretsStore interface {
	List(orgID string) ([]bwSecret, error)
	Get(secretID string) (*bwSecret, error)
	Create(key, value, note, orgID string, projectIDs []string) (*bwSecret, error)
	Update(secretID, key, value, note, orgID string, projectIDs []string) (*bwSecret, error)
	Close()
}

type BWClient struct {
	store     bwSecretsStore
	orgID     string
	closeOnce sync.Once
}

func newBWClientWithStore(store bwSecretsStore, orgID string) *BWClient {
	c := &BWClient{
		store: store,
		orgID: orgID,
	}
	runtime.SetFinalizer(c, func(bw *BWClient) { bw.Close() })
	return c
}

// Close releases the underlying Bitwarden SDK client resources.
func (bw *BWClient) Close() {
	if bw == nil {
		return
	}
	bw.closeOnce.Do(func() {
		runtime.SetFinalizer(bw, nil)
		if bw.store != nil {
			bw.store.Close()
			bw.store = nil
		}
	})
}

func (bw *BWClient) secretKey(deviceID string) string {
	return "laps/" + deviceID
}

func (bw *BWClient) projectIDs(vaultID string) []string {
	if strings.TrimSpace(vaultID) == "" {
		return nil
	}
	return []string{vaultID}
}

func (bw *BWClient) findSecretID(deviceID string) (string, error) {
	defer runtime.KeepAlive(bw)
	items, err := bw.store.List(bw.orgID)
	if err != nil {
		return "", fmt.Errorf("failed to list Bitwarden secrets: %w", err)
	}
	wantPrefixed := bw.secretKey(deviceID)
	for _, item := range items {
		if strings.EqualFold(item.Key, wantPrefixed) || strings.EqualFold(item.Key, deviceID) {
			return item.ID, nil
		}
	}
	return "", nil
}

// readData returns the current secret key and decoded JSON map.
func (bw *BWClient) readData(secretID string) (string, map[string]string, error) {
	defer runtime.KeepAlive(bw)
	sec, err := bw.store.Get(secretID)
	if err != nil {
		return "", nil, err
	}
	data := map[string]string{}
	key := ""
	if sec != nil {
		key = sec.Key
		if strings.TrimSpace(sec.Value) != "" {
			if err := json.Unmarshal([]byte(sec.Value), &data); err != nil {
				return "", nil, fmt.Errorf("failed to decode Bitwarden secret %s: %w", secretID, err)
			}
		}
	}
	return key, data, nil
}

func (bw *BWClient) writeData(creds *Credentials, key, vaultID string, data map[string]string) error {
	defer runtime.KeepAlive(bw)
	raw, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal Bitwarden secret data: %w", err)
	}
	note := "Managed by GoLAPS"
	projects := bw.projectIDs(vaultID)

	if creds.ItemID != "" {
		if _, err := bw.store.Update(creds.ItemID, key, string(raw), note, bw.orgID, projects); err != nil {
			return fmt.Errorf("failed to update Bitwarden secret %s: %w", creds.ItemID, err)
		}
		return nil
	}

	created, err := bw.store.Create(key, string(raw), note, bw.orgID, projects)
	if err != nil {
		return fmt.Errorf("failed to create Bitwarden secret %s: %w", key, err)
	}
	if created != nil {
		creds.ItemID = created.ID
	}
	return nil
}

func (bw *BWClient) resolveKey(existingKey string, data map[string]string, deviceID string) string {
	if existingKey != "" {
		return existingKey
	}
	if deviceID != "" {
		return bw.secretKey(deviceID)
	}
	if s := data["serial"]; s != "" {
		return bw.secretKey(s)
	}
	return ""
}

func (bw *BWClient) GetCredentials(ctx context.Context, deviceID, vaultID, targetAdmin string) (*Credentials, error) {
	if err := ctx.Err(); err != nil {
		return &Credentials{OldLogin: targetAdmin}, err
	}
	res := &Credentials{OldLogin: targetAdmin}

	id, err := bw.findSecretID(deviceID)
	if err != nil {
		return res, err
	}
	if id == "" {
		return res, nil
	}
	res.ItemID = id

	_, data, err := bw.readData(id)
	if err != nil {
		return res, err
	}
	if v := data["login"]; v != "" {
		res.OldLogin = v
	}
	if v := data["password"]; v != "" {
		res.OldPassword = v
	}
	if v := data["pending_password"]; v != "" {
		res.PendingPassword = v
	}
	if v := data["previous_pending_password"]; v != "" {
		res.PreviousPendingPassword = v
	}
	if v := data["bridge_password"]; v != "" {
		res.BridgePassword = v
	}
	if v := data["legacy_login"]; v != "" {
		res.LegacyLogin = v
	}
	if v := data["legacy_password"]; v != "" {
		res.LegacyPassword = v
	}
	if res.OldLogin != "" && res.OldLogin != targetAdmin {
		res.IsMigration = true
	}
	return res, nil
}

func (bw *BWClient) StagePendingPassword(ctx context.Context, creds *Credentials, deviceID, hostname, vaultID, newLogin, newPassword string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	existingKey := ""
	data := map[string]string{}
	if creds.ItemID != "" {
		var err error
		existingKey, data, err = bw.readData(creds.ItemID)
		if err != nil {
			return fmt.Errorf("could not read Bitwarden secret before staging: %w", err)
		}
	}
	data["hostname"] = hostname
	data["serial"] = deviceID
	if old := data["pending_password"]; old != "" && old != newPassword {
		data["previous_pending_password"] = old
	}
	data["pending_password"] = newPassword
	return bw.writeData(creds, bw.resolveKey(existingKey, data, deviceID), vaultID, data)
}

func (bw *BWClient) ClearPendingPassword(ctx context.Context, creds *Credentials, vaultID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if creds.ItemID == "" {
		return nil
	}
	existingKey, data, err := bw.readData(creds.ItemID)
	if err != nil {
		return err
	}
	delete(data, "pending_password")
	if prev := data["previous_pending_password"]; prev != "" {
		data["pending_password"] = prev
		delete(data, "previous_pending_password")
	}
	return bw.writeData(creds, bw.resolveKey(existingKey, data, ""), vaultID, data)
}

func (bw *BWClient) ConfirmLivePassword(ctx context.Context, creds *Credentials, deviceID, hostname, vaultID, login, live string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if creds.ItemID == "" {
		return fmt.Errorf("device %s has no Bitwarden secret; cannot confirm live password", deviceID)
	}
	existingKey, data, err := bw.readData(creds.ItemID)
	if err != nil {
		return err
	}
	if creds.IsMigration && creds.OldLogin != "" && data["legacy_login"] == "" {
		data["legacy_login"] = creds.OldLogin
		data["legacy_password"] = creds.OldPassword
	}
	data["hostname"] = hostname
	data["serial"] = deviceID
	data["login"] = login
	data["password"] = live
	delete(data, "pending_password")
	delete(data, "previous_pending_password")
	if err := bw.writeData(creds, bw.resolveKey(existingKey, data, deviceID), vaultID, data); err != nil {
		return err
	}
	creds.recordConfirmed(login, live)
	return nil
}

func (bw *BWClient) StageBridgePassword(ctx context.Context, creds *Credentials, vaultID, password string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if creds.ItemID == "" {
		return fmt.Errorf("device has no Bitwarden secret yet; cannot escrow bridge password")
	}
	existingKey, data, err := bw.readData(creds.ItemID)
	if err != nil {
		return err
	}
	data["bridge_password"] = password
	if err := bw.writeData(creds, bw.resolveKey(existingKey, data, ""), vaultID, data); err != nil {
		return err
	}
	creds.BridgePassword = password
	return nil
}

func (bw *BWClient) ClearBridgePassword(ctx context.Context, creds *Credentials, vaultID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if creds.ItemID == "" {
		return nil
	}
	existingKey, data, err := bw.readData(creds.ItemID)
	if err != nil {
		return err
	}
	delete(data, "bridge_password")
	if err := bw.writeData(creds, bw.resolveKey(existingKey, data, ""), vaultID, data); err != nil {
		return err
	}
	creds.BridgePassword = ""
	return nil
}

func (bw *BWClient) UpsertCredentials(ctx context.Context, creds *Credentials, deviceID, hostname, vaultID, newLogin, newPassword, tokenStatus string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	existingKey := ""
	data := map[string]string{}
	if creds.ItemID != "" {
		var err error
		existingKey, data, err = bw.readData(creds.ItemID)
		if err != nil {
			return err
		}
	}
	if creds.IsMigration && creds.OldLogin != "" && data["legacy_login"] == "" {
		data["legacy_login"] = creds.OldLogin
		data["legacy_password"] = creds.OldPassword
	}
	data["hostname"] = hostname
	data["serial"] = deviceID
	data["login"] = newLogin
	data["password"] = newPassword
	data["secure_token"] = tokenStatus
	data["updated_at"] = time.Now().Format(time.RFC3339)
	delete(data, "pending_password")
	delete(data, "previous_pending_password")
	return bw.writeData(creds, bw.resolveKey(existingKey, data, deviceID), vaultID, data)
}

var _ Client = (*BWClient)(nil)
