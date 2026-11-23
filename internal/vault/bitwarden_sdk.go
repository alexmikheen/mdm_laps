// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

//go:build cgo && bitwarden_sdk

package vault

import (
	"fmt"
	"os"
	"strings"

	sdk "github.com/bitwarden/sdk-go/v2"
)

type bwSDKStore struct {
	client sdk.BitwardenClientInterface
}

func (s *bwSDKStore) List(orgID string) ([]bwSecret, error) {
	resp, err := s.client.Secrets().List(orgID)
	if err != nil {
		return nil, err
	}
	out := make([]bwSecret, 0, len(resp.Data))
	for _, item := range resp.Data {
		out = append(out, bwSecret{ID: item.ID, Key: item.Key})
	}
	return out, nil
}

func (s *bwSDKStore) Get(secretID string) (*bwSecret, error) {
	resp, err := s.client.Secrets().Get(secretID)
	if err != nil {
		return nil, err
	}
	return &bwSecret{ID: resp.ID, Key: resp.Key, Value: resp.Value, Note: resp.Note}, nil
}

func (s *bwSDKStore) Create(key, value, note, orgID string, projectIDs []string) (*bwSecret, error) {
	resp, err := s.client.Secrets().Create(key, value, note, orgID, projectIDs)
	if err != nil {
		return nil, err
	}
	return &bwSecret{ID: resp.ID, Key: resp.Key, Value: resp.Value, Note: resp.Note}, nil
}

func (s *bwSDKStore) Update(secretID, key, value, note, orgID string, projectIDs []string) (*bwSecret, error) {
	resp, err := s.client.Secrets().Update(secretID, key, value, note, orgID, projectIDs)
	if err != nil {
		return nil, err
	}
	return &bwSecret{ID: resp.ID, Key: resp.Key, Value: resp.Value, Note: resp.Note}, nil
}

func (s *bwSDKStore) Close() {
	s.client.Close()
}

// NewBitwardenClient authenticates with Bitwarden Secrets Manager using the official SDK (v2)
// and a Machine Account Access Token (BWS_ACCESS_TOKEN / BW_API_KEY / LAPS_VAULT_TOKEN).
func NewBitwardenClient(serverURL, accessToken, orgID string) (*BWClient, error) {
	if strings.TrimSpace(accessToken) == "" {
		return nil, fmt.Errorf("Bitwarden Secrets Manager access token is required (set BWS_ACCESS_TOKEN, BW_API_KEY, or LAPS_VAULT_TOKEN)")
	}
	if strings.TrimSpace(orgID) == "" {
		return nil, fmt.Errorf("Bitwarden organization ID is required (set BW_ORG_ID)")
	}

	apiURL := strings.TrimSpace(serverURL)
	if apiURL == "" {
		apiURL = "https://api.bitwarden.com"
	}
	identityURL := strings.TrimSpace(os.Getenv("BW_IDENTITY_URL"))
	if identityURL == "" {
		identityURL = "https://identity.bitwarden.com"
	}

	client, err := sdk.NewBitwardenClient(&apiURL, &identityURL)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Bitwarden SDK client: %w", err)
	}
	if err := client.AccessTokenLogin(accessToken, nil); err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to authenticate with Bitwarden Secrets Manager: %w", err)
	}

	return newBWClientWithStore(&bwSDKStore{client: client}, orgID), nil
}
