// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
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
	if endpoint := os.Getenv("AWS_ENDPOINT_URL"); endpoint != "" {
		cfgOptions = append(cfgOptions, config.WithEndpointResolverWithOptions(
			aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
				return aws.Endpoint{URL: endpoint, SigningRegion: region, HostnameImmutable: true}, nil
			}),
		))
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
// It returns network and IAM permission errors so the orchestrator aborts instead of rotating without a working escrow.
func (awsClient *AWSClient) readData(ctx context.Context, secretName string) (map[string]string, error) {
	result, err := awsClient.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretName),
	})
	if err != nil {
		var notFound *types.ResourceNotFoundException
		if errors.As(err, &notFound) {
			return map[string]string{}, nil
		}
		return nil, err
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
		var notFound *types.ResourceNotFoundException
		if errors.As(err, &notFound) {
			_, err = awsClient.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
				Name:         aws.String(secretName),
				SecretString: aws.String(secretString),
				Description:  aws.String(fmt.Sprintf("LAPS credentials for device %s", secretName)),
			})
		}
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
	if old := secretData["pending_password"]; old != "" && old != newPassword {
		secretData["previous_pending_password"] = old
	}
	secretData["pending_password"] = newPassword

	if err := awsClient.writeData(ctx, secretName, secretData); err != nil {
		return fmt.Errorf("could not stage the pending password: %w", err)
	}
	creds.ItemID = secretName
	return nil
}

// ClearPendingPassword deletes the staged value after a policy-rejected rotation.
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
	if prev := secretData["previous_pending_password"]; prev != "" {
		secretData["pending_password"] = prev
		delete(secretData, "previous_pending_password")
	}
	return awsClient.writeData(ctx, creds.ItemID, secretData)
}

func (awsClient *AWSClient) ConfirmLivePassword(ctx context.Context, creds *Credentials, deviceID, hostname, vaultID, login, live string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	secretName := fmt.Sprintf("laps/%s", deviceID)
	secretData, err := awsClient.readData(ctx, secretName)
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
	if err := awsClient.writeData(ctx, secretName, secretData); err != nil {
		return err
	}
	creds.recordConfirmed(login, live)
	return nil
}

func (awsClient *AWSClient) StageBridgePassword(ctx context.Context, creds *Credentials, vaultID, password string) error {
	if creds.ItemID == "" {
		return fmt.Errorf("device has no vault record yet; cannot escrow bridge password")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	secretData, err := awsClient.readData(ctx, creds.ItemID)
	if err != nil {
		return err
	}
	secretData["bridge_password"] = password
	if err := awsClient.writeData(ctx, creds.ItemID, secretData); err != nil {
		return err
	}
	creds.BridgePassword = password
	return nil
}

func (awsClient *AWSClient) ClearBridgePassword(ctx context.Context, creds *Credentials, vaultID string) error {
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
		creds.BridgePassword = ""
		return nil
	}
	delete(secretData, "bridge_password")
	if err := awsClient.writeData(ctx, creds.ItemID, secretData); err != nil {
		return err
	}
	creds.BridgePassword = ""
	return nil
}

func (awsClient *AWSClient) UpsertCredentials(ctx context.Context, creds *Credentials, deviceID, hostname, vaultID, newLogin, newPassword, tokenStatus string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	secretName := fmt.Sprintf("laps/%s", deviceID)
	// Read and update the existing secret so bridge_password and legacy_* fields survive until explicitly cleared.
	secretData, err := awsClient.readData(ctx, secretName)
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
	secretData["region"] = awsClient.region
	delete(secretData, "pending_password")
	delete(secretData, "previous_pending_password")

	return awsClient.writeData(ctx, secretName, secretData)
}

// Ensure interface compliance
var _ Client = (*AWSClient)(nil)
