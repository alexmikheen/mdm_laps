// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

//go:build integration

package vault

import (
	"context"
	"crypto/tls"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
)

func runFullClientLifecycle(t *testing.T, client Client, vaultID string) {
	t.Helper()
	ctx := context.Background()
	deviceID := "C02TEST12345"
	hostname := "test-macbook"
	admin := "localadmin"

	creds, err := client.GetCredentials(ctx, deviceID, vaultID, admin)
	if err != nil {
		t.Fatalf("initial GetCredentials failed: %v", err)
	}
	if creds.OldPassword != "" {
		t.Fatalf("expected empty initial password, got %q", creds.OldPassword)
	}

	if err := client.StagePendingPassword(ctx, creds, deviceID, hostname, vaultID, admin, "PendingPass#1"); err != nil {
		t.Fatalf("StagePendingPassword #1 failed: %v", err)
	}
	if creds.ItemID == "" {
		t.Fatalf("StagePendingPassword did not populate creds.ItemID")
	}

	read1, err := client.GetCredentials(ctx, deviceID, vaultID, admin)
	if err != nil {
		t.Fatalf("GetCredentials after stage #1 failed: %v", err)
	}
	if read1.PendingPassword != "PendingPass#1" {
		t.Fatalf("PendingPassword = %q, want PendingPass#1", read1.PendingPassword)
	}

	if err := client.StagePendingPassword(ctx, read1, deviceID, hostname, vaultID, admin, "PendingPass#2"); err != nil {
		t.Fatalf("StagePendingPassword #2 failed: %v", err)
	}
	read2, err := client.GetCredentials(ctx, deviceID, vaultID, admin)
	if err != nil {
		t.Fatalf("GetCredentials after stage #2 failed: %v", err)
	}
	if read2.PendingPassword != "PendingPass#2" || read2.PreviousPendingPassword != "PendingPass#1" {
		t.Fatalf("after stage #2: pending=%q prev=%q, want PendingPass#2 / PendingPass#1", read2.PendingPassword, read2.PreviousPendingPassword)
	}

	if err := client.ClearPendingPassword(ctx, read2, vaultID); err != nil {
		t.Fatalf("ClearPendingPassword failed: %v", err)
	}
	read3, err := client.GetCredentials(ctx, deviceID, vaultID, admin)
	if err != nil {
		t.Fatalf("GetCredentials after ClearPendingPassword failed: %v", err)
	}
	if read3.PendingPassword != "PendingPass#1" || read3.PreviousPendingPassword != "" {
		t.Fatalf("after clear: pending=%q prev=%q, want PendingPass#1 / empty", read3.PendingPassword, read3.PreviousPendingPassword)
	}

	if err := client.ConfirmLivePassword(ctx, read3, deviceID, hostname, vaultID, admin, "PendingPass#1"); err != nil {
		t.Fatalf("ConfirmLivePassword failed: %v", err)
	}
	read4, err := client.GetCredentials(ctx, deviceID, vaultID, admin)
	if err != nil {
		t.Fatalf("GetCredentials after ConfirmLivePassword failed: %v", err)
	}
	if read4.OldPassword != "PendingPass#1" || read4.PendingPassword != "" || read4.PreviousPendingPassword != "" {
		t.Fatalf("after confirm: old=%q pending=%q prev=%q", read4.OldPassword, read4.PendingPassword, read4.PreviousPendingPassword)
	}

	if err := client.StageBridgePassword(ctx, read4, vaultID, "BridgePass#1"); err != nil {
		t.Fatalf("StageBridgePassword failed: %v", err)
	}
	read5, err := client.GetCredentials(ctx, deviceID, vaultID, admin)
	if err != nil {
		t.Fatalf("GetCredentials after StageBridgePassword failed: %v", err)
	}
	if read5.BridgePassword != "BridgePass#1" {
		t.Fatalf("BridgePassword = %q, want BridgePass#1", read5.BridgePassword)
	}
	if err := client.ClearBridgePassword(ctx, read5, vaultID); err != nil {
		t.Fatalf("ClearBridgePassword failed: %v", err)
	}
	read6, err := client.GetCredentials(ctx, deviceID, vaultID, admin)
	if err != nil {
		t.Fatalf("GetCredentials after ClearBridgePassword failed: %v", err)
	}
	if read6.BridgePassword != "" {
		t.Fatalf("BridgePassword = %q after clear, want empty", read6.BridgePassword)
	}

	if err := client.UpsertCredentials(ctx, read6, deviceID, hostname, vaultID, admin, "FinalPass#9", "ENABLED"); err != nil {
		t.Fatalf("UpsertCredentials failed: %v", err)
	}
	final, err := client.GetCredentials(ctx, deviceID, vaultID, admin)
	if err != nil {
		t.Fatalf("final GetCredentials failed: %v", err)
	}
	if final.OldLogin != admin || final.OldPassword != "FinalPass#9" || final.PendingPassword != "" {
		t.Fatalf("final state mismatch: login=%q pass=%q pending=%q", final.OldLogin, final.OldPassword, final.PendingPassword)
	}
}

func TestHashiCorpVaultIntegration(t *testing.T) {
	addr := os.Getenv("TEST_VAULT_ADDR")
	if addr == "" {
		addr = "http://127.0.0.1:18200"
	}
	token := os.Getenv("TEST_VAULT_TOKEN")
	if token == "" {
		token = "golaps-root-token"
	}

	client, err := NewHashiCorpClient(addr, token, "secret/data/laps")
	if err != nil {
		t.Fatalf("NewHashiCorpClient(%s) failed: %v", addr, err)
	}
	runFullClientLifecycle(t, client, "secret/data/laps")
}

func TestAWSSecretsManagerIntegration(t *testing.T) {
	endpoint := os.Getenv("AWS_ENDPOINT_URL")
	if endpoint == "" {
		t.Setenv("AWS_ENDPOINT_URL", "http://127.0.0.1:15000")
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "testing")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "testing")

	client, err := NewAWSClient("us-east-1", "")
	if err != nil {
		t.Fatalf("NewAWSClient failed: %v", err)
	}
	runFullClientLifecycle(t, client, "us-east-1")
}

type fakeAzureCred struct{}

func (fakeAzureCred) GetToken(_ context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "dummy-token", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func TestAzureKeyVaultIntegration(t *testing.T) {
	vaultURL := os.Getenv("TEST_AZURE_VAULT_URL")
	if vaultURL == "" {
		vaultURL = "https://127.0.0.1:18443"
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // self-signed cert of local lowkey-vault emulator
		},
	}
	opts := &azsecrets.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: httpClient,
		},
		DisableChallengeResourceVerification: true,
	}

	client, err := NewAzureClientWithCredential(vaultURL, fakeAzureCred{}, opts)
	if err != nil {
		t.Fatalf("NewAzureClientWithCredential(%s) failed: %v", vaultURL, err)
	}
	runFullClientLifecycle(t, client, "golaps")
}
