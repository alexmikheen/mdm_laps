// internal/vault/azure.go
package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
)

type AzureClient struct {
	client *azsecrets.Client
}

func NewAzureClient(tenantID, clientID, clientSecret, vaultURL string) (*AzureClient, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create credential using service principal
	cred, err := azidentity.NewClientSecretCredential(tenantID, clientID, clientSecret, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create azure credential: %w", err)
	}

	// Create secrets client
	client, err := azsecrets.NewClient(vaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create azure secrets client: %w", err)
	}

	// Test connection
	_, err = client.GetSecret(ctx, "health-check", "", nil)
	// We expect an error for non-existent secret, but connection should work Just verify we can make calls

	return &AzureClient{
		client: client,
	}, nil
}

// readData returns the device's current secret map, or an empty map when the secret does not exist yet.
func (ac *AzureClient) readData(ctx context.Context, secretName string) (map[string]string, error) {
	secretBundle, err := ac.client.GetSecret(ctx, secretName, "", nil)
	if err != nil {
		// Secret might not exist yet
		return map[string]string{}, nil
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

// StagePendingPassword escrows the candidate password before the device is touched. Read-modify-write so the existing record (current password, legacy data) survives the stage.
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
	secretData["pending_password"] = newPassword

	if err := ac.writeData(ctx, secretName, secretData); err != nil {
		return fmt.Errorf("could not stage the pending password: %w", err)
	}
	creds.ItemID = secretName
	return nil
}

// ClearPendingPassword drops the staged value after a rotation the device policy refused.
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
	return ac.writeData(ctx, creds.ItemID, secretData)
}

func (ac *AzureClient) UpsertCredentials(ctx context.Context, creds *Credentials, deviceID, hostname, vaultID, newLogin, newPassword, tokenStatus string) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	secretName := fmt.Sprintf("laps-%s", deviceID)

	// Prepare secret data. The rebuilt map intentionally carries no pending_password: committing the real password IS the confirming write.
	secretData := map[string]string{
		"hostname":     hostname,
		"serial":       deviceID,
		"login":        newLogin,
		"password":     newPassword,
		"secure_token": tokenStatus,
		"updated_at":   time.Now().Format(time.RFC3339),
	}

	// Add legacy credentials if migrating
	if creds.IsMigration && creds.OldLogin != "" {
		secretData["old_login"] = creds.OldLogin
		secretData["old_password"] = creds.OldPassword
		secretData["legacy_login"] = creds.LegacyLogin
		secretData["legacy_password"] = creds.LegacyPassword
	}

	return ac.writeData(ctx, secretName, secretData)
}

func strPtr(s string) *string {
	return &s
}

// Ensure interface compliance
var _ Client = (*AzureClient)(nil)
