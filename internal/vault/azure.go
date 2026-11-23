// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
)

type AzureClient struct {
	client *azsecrets.Client
}

func NewAzureClient(tenantID, clientID, clientSecret, vaultURL string) (*AzureClient, error) {
	cred, err := azidentity.NewClientSecretCredential(tenantID, clientID, clientSecret, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create azure credential: %w", err)
	}
	return NewAzureClientWithCredential(vaultURL, cred, nil)
}

// NewAzureClientWithCredential builds an AzureClient with any azcore.TokenCredential and optional ClientOptions (enabling managed identities, custom HTTP transports, or local emulators such as lowkey-vault).
func NewAzureClientWithCredential(vaultURL string, cred azcore.TokenCredential, opts *azsecrets.ClientOptions) (*AzureClient, error) {
	client, err := azsecrets.NewClient(vaultURL, cred, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create azure secrets client: %w", err)
	}

	return &AzureClient{
		client: client,
	}, nil
}

// readData returns the device's current secret map, or an empty map when the secret does not exist yet (HTTP 404).
// Auth, permission, and connectivity errors are propagated so GoLAPS aborts before rotating.
func (ac *AzureClient) readData(ctx context.Context, secretName string) (map[string]string, error) {
	secretBundle, err := ac.client.GetSecret(ctx, secretName, "", nil)
	if err != nil {
		var respErr *azcore.ResponseError
		if errors.As(err, &respErr) && respErr.StatusCode == http.StatusNotFound {
			return map[string]string{}, nil
		}
		return nil, err
	}
	secretData := map[string]string{}
	if secretBundle.Value != nil {
		if err := json.Unmarshal([]byte(*secretBundle.Value), &secretData); err != nil {
			return nil, err
		}
	}
	return secretData, nil
}

func (ac *AzureClient) writeData(ctx context.Context, secretName string, secretData map[string]string) error {
	secretJSON, err := json.Marshal(secretData)
	if err != nil {
		return fmt.Errorf("failed to marshal secret data: %w", err)
	}
	secretString := string(secretJSON)

	parameters := azsecrets.SetSecretParameters{
		Value: &secretString,
		Tags: map[string]*string{
			"ManagedBy": strPtr("GoLAPS"),
			"Type":      strPtr("LAPS"),
		},
	}
	_, err = ac.client.SetSecret(ctx, secretName, parameters, nil)
	return err
}

func (ac *AzureClient) GetCredentials(ctx context.Context, deviceID, vaultID, targetAdmin string) (*Credentials, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	res := &Credentials{OldLogin: targetAdmin}

	// Secret name format: laps-{deviceID}
	secretName := fmt.Sprintf("laps-%s", deviceID)

	secretData, err := ac.readData(ctx, secretName)
	if err != nil {
		return res, err
	}
	if len(secretData) == 0 {
		return res, nil
	}
	res.ItemID = secretName

	if oldLogin, ok := secretData["login"]; ok && oldLogin != "" {
		res.OldLogin = oldLogin
	}
	if oldPassword, ok := secretData["password"]; ok && oldPassword != "" {
		res.OldPassword = oldPassword
	}
	if pending, ok := secretData["pending_password"]; ok && pending != "" {
		res.PendingPassword = pending
	}
	if prevPending, ok := secretData["previous_pending_password"]; ok && prevPending != "" {
		res.PreviousPendingPassword = prevPending
	}
	if bridgePass, ok := secretData["bridge_password"]; ok && bridgePass != "" {
		res.BridgePassword = bridgePass
	}
	if legacyLogin, ok := secretData["legacy_login"]; ok && legacyLogin != "" {
		res.LegacyLogin = legacyLogin
	}
	if legacyPassword, ok := secretData["legacy_password"]; ok && legacyPassword != "" {
		res.LegacyPassword = legacyPassword
	}

	// Check for migration
	if res.OldLogin != "" && res.OldLogin != targetAdmin {
		res.IsMigration = true
	}

	return res, nil
}

// StagePendingPassword stores the candidate before OS rotation and preserves existing fields.
func (ac *AzureClient) StagePendingPassword(ctx context.Context, creds *Credentials, deviceID, hostname, vaultID, newLogin, newPassword string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	secretName := fmt.Sprintf("laps-%s", deviceID)
	secretData, err := ac.readData(ctx, secretName)
	if err != nil {
		return fmt.Errorf("could not read the device secret before staging: %w", err)
	}
	secretData["hostname"] = hostname
	secretData["serial"] = deviceID
	if old := secretData["pending_password"]; old != "" && old != newPassword {
		secretData["previous_pending_password"] = old
	}
	secretData["pending_password"] = newPassword

	if err := ac.writeData(ctx, secretName, secretData); err != nil {
		return fmt.Errorf("could not stage the pending password: %w", err)
	}
	creds.ItemID = secretName
	return nil
}

// ClearPendingPassword removes the staged value after a policy-rejected rotation.
func (ac *AzureClient) ClearPendingPassword(ctx context.Context, creds *Credentials, vaultID string) error {
	if creds.ItemID == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	secretData, err := ac.readData(ctx, creds.ItemID)
	if err != nil {
		return err
	}
	if len(secretData) == 0 {
		return nil
	}
	delete(secretData, "pending_password")
	if prev := secretData["previous_pending_password"]; prev != "" {
		secretData["pending_password"] = prev
		delete(secretData, "previous_pending_password")
	}
	return ac.writeData(ctx, creds.ItemID, secretData)
}

func (ac *AzureClient) ConfirmLivePassword(ctx context.Context, creds *Credentials, deviceID, hostname, vaultID, login, live string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	secretName := fmt.Sprintf("laps-%s", deviceID)
	secretData, err := ac.readData(ctx, secretName)
	if err != nil {
		return err
	}
	if creds.IsMigration && creds.OldLogin != "" && secretData["legacy_login"] == "" {
		secretData["legacy_login"] = creds.OldLogin
		secretData["legacy_password"] = creds.OldPassword
	}
	secretData["hostname"] = hostname
	secretData["serial"] = deviceID
	secretData["login"] = login
	secretData["password"] = live
	delete(secretData, "pending_password")
	delete(secretData, "previous_pending_password")
	if err := ac.writeData(ctx, secretName, secretData); err != nil {
		return err
	}
	creds.recordConfirmed(login, live)
	return nil
}

func (ac *AzureClient) StageBridgePassword(ctx context.Context, creds *Credentials, vaultID, password string) error {
	if creds.ItemID == "" {
		return fmt.Errorf("device has no vault record yet; cannot escrow bridge password")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	secretData, err := ac.readData(ctx, creds.ItemID)
	if err != nil {
		return err
	}
	secretData["bridge_password"] = password
	if err := ac.writeData(ctx, creds.ItemID, secretData); err != nil {
		return err
	}
	creds.BridgePassword = password
	return nil
}

func (ac *AzureClient) ClearBridgePassword(ctx context.Context, creds *Credentials, vaultID string) error {
	if creds.ItemID == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	secretData, err := ac.readData(ctx, creds.ItemID)
	if err != nil {
		return err
	}
	if len(secretData) == 0 {
		creds.BridgePassword = ""
		return nil
	}
	delete(secretData, "bridge_password")
	if err := ac.writeData(ctx, creds.ItemID, secretData); err != nil {
		return err
	}
	creds.BridgePassword = ""
	return nil
}

func (ac *AzureClient) UpsertCredentials(ctx context.Context, creds *Credentials, deviceID, hostname, vaultID, newLogin, newPassword, tokenStatus string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	secretName := fmt.Sprintf("laps-%s", deviceID)
	// Read-modify-write so bridge_password and existing legacy_* fields survive until explicitly cleared.
	secretData, err := ac.readData(ctx, secretName)
	if err != nil {
		return err
	}
	if creds.IsMigration && creds.OldLogin != "" && secretData["legacy_login"] == "" {
		secretData["legacy_login"] = creds.OldLogin
		secretData["legacy_password"] = creds.OldPassword
	}
	secretData["hostname"] = hostname
	secretData["serial"] = deviceID
	secretData["login"] = newLogin
	secretData["password"] = newPassword
	secretData["secure_token"] = tokenStatus
	secretData["updated_at"] = time.Now().Format(time.RFC3339)
	delete(secretData, "pending_password")
	delete(secretData, "previous_pending_password")

	return ac.writeData(ctx, secretName, secretData)
}

func strPtr(s string) *string {
	return &s
}

// Ensure interface compliance
var _ Client = (*AzureClient)(nil)
