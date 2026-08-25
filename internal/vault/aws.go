// internal/vault/aws.go
package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type AWSClient struct {
	client *secretsmanager.Client
	region string
}

func NewAWSClient(region, profile string) (*AWSClient, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Load AWS configuration using default credential chain
	cfgOptions := []func(*config.LoadOptions) error{
		config.WithRegion(region),
	}

	if profile != "" {
		cfgOptions = append(cfgOptions, config.WithSharedConfigProfile(profile))
	}

	cfg, err := config.LoadDefaultConfig(ctx, cfgOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := secretsmanager.NewFromConfig(cfg)

	return &AWSClient{
		client: client,
		region: region,
	}, nil
}

// readData returns the device's current secret map, or an empty map when the secret does not exist yet.
func (awsClient *AWSClient) readData(ctx context.Context, secretName string) (map[string]string, error) {
	result, err := awsClient.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretName),
	})
	if err != nil {
		// Secret might not exist yet
		return map[string]string{}, nil
	}
	secretData := map[string]string{}
	if result.SecretString != nil {
		if err := json.Unmarshal([]byte(*result.SecretString), &secretData); err != nil {
			return nil, err
		}
	}
	return secretData, nil
}

// writeData updates the secret, creating it when it does not exist yet.
func (awsClient *AWSClient) writeData(ctx context.Context, secretName string, secretData map[string]string) error {
	secretJSON, err := json.Marshal(secretData)
	if err != nil {
		return fmt.Errorf("failed to marshal secret data: %w", err)
	}
	secretString := string(secretJSON)

	_, err = awsClient.client.UpdateSecret(ctx, &secretsmanager.UpdateSecretInput{
		SecretId:     aws.String(secretName),
		SecretString: aws.String(secretString),
	})
	if err != nil {
		// If secret doesn't exist, create it
		_, err = awsClient.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String(secretName),
			SecretString: aws.String(secretString),
			Description:  aws.String(fmt.Sprintf("LAPS credentials for device %s", secretName)),
		})
	}
	return err
}

func (awsClient *AWSClient) GetCredentials(ctx context.Context, deviceID, vaultID, targetAdmin string) (*Credentials, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	res := &Credentials{OldLogin: targetAdmin}

	// Secret name format: laps/{deviceID}
	secretName := fmt.Sprintf("laps/%s", deviceID)

	secretData, err := awsClient.readData(ctx, secretName)
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

// StagePendingPassword escrows the candidate password before the device is touched.
// Read-modify-write so the existing record (current password, legacy data) survives the stage.
func (awsClient *AWSClient) StagePendingPassword(ctx context.Context, creds *Credentials, deviceID, hostname, vaultID, newLogin, newPassword string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	secretName := fmt.Sprintf("laps/%s", deviceID)
	secretData, err := awsClient.readData(ctx, secretName)
	if err != nil {
		return fmt.Errorf("could not read the device secret before staging: %w", err)
	}
	secretData["hostname"] = hostname
	secretData["serial"] = deviceID
	secretData["pending_password"] = newPassword

	if err := awsClient.writeData(ctx, secretName, secretData); err != nil {
		return fmt.Errorf("could not stage the pending password: %w", err)
	}
	creds.ItemID = secretName
	return nil
}

// ClearPendingPassword drops the staged value after a rotation the device policy refused.
func (awsClient *AWSClient) ClearPendingPassword(ctx context.Context, creds *Credentials, vaultID string) error {
	if creds.ItemID == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	secretData, err := awsClient.readData(ctx, creds.ItemID)
	if err != nil {
		return err
	}
	if len(secretData) == 0 {
		return nil
	}
	delete(secretData, "pending_password")
	return awsClient.writeData(ctx, creds.ItemID, secretData)
}

func (awsClient *AWSClient) UpsertCredentials(ctx context.Context, creds *Credentials, deviceID, hostname, vaultID, newLogin, newPassword, tokenStatus string) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	secretName := fmt.Sprintf("laps/%s", deviceID)

	// Prepare secret data. The rebuilt map intentionally carries no
	// pending_password: committing the real password IS the confirming write.
	secretData := map[string]string{
		"hostname":     hostname,
		"serial":       deviceID,
		"login":        newLogin,
		"password":     newPassword,
		"secure_token": tokenStatus,
		"updated_at":   time.Now().Format(time.RFC3339),
		"region":       awsClient.region,
	}

	// Add legacy credentials if migrating
	if creds.IsMigration && creds.OldLogin != "" {
		secretData["old_login"] = creds.OldLogin
		secretData["old_password"] = creds.OldPassword
		secretData["legacy_login"] = creds.LegacyLogin
		secretData["legacy_password"] = creds.LegacyPassword
	}

	return awsClient.writeData(ctx, secretName, secretData)
}

// Ensure interface compliance
var _ Client = (*AWSClient)(nil)
