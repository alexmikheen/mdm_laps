// internal/vault/bitwarden.go
package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type BWClient struct {
	httpClient *http.Client
	apiKey     string
	serverURL  string
	orgID      string
	token      string
}

type BWTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

type BWItem struct {
	ID            string       `json:"id"`
	Name          string       `json:"name"`
	Login         BWLogin      `json:"login,omitempty"`
	SecureNote    BWSecureNote `json:"secureNote,omitempty"`
	CollectionIDs []string     `json:"collectionIds,omitempty"`
	Fields        []BWField    `json:"fields,omitempty"`
}

type BWLogin struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type BWSecureNote struct {
	Type int `json:"type"`
}

type BWField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Type  int    `json:"type"` // 0=Text, 1=Hidden
}

type BWSecretRequest struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func NewBitwardenClient(serverURL, apiKey, orgID string) (*BWClient, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := &BWClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		apiKey:     apiKey,
		serverURL:  serverURL,
		orgID:      orgID,
	}

	// Get access token using API key
	if err := client.authenticate(ctx); err != nil {
		return nil, fmt.Errorf("failed to authenticate with Bitwarden: %w", err)
	}

	return client, nil
}

func (bw *BWClient) authenticate(ctx context.Context) error {
	url := fmt.Sprintf("%s/identity/connect/token", bw.serverURL)

	data := fmt.Sprintf(
		"grant_type=client_credentials&client_id=%s&client_secret=%s&scope=api.secrets",
		bw.apiKey[:36], // client_id is first 36 chars
		bw.apiKey[37:], // client_secret is after colon
	)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBufferString(data))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := bw.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authentication failed: %s", string(body))
	}

	var tokenResp BWTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return err
	}

	bw.token = tokenResp.AccessToken
	return nil
}

// getItem fetches a single item by ID.
func (bw *BWClient) getItem(ctx context.Context, itemID string) (*BWItem, error) {
	url := fmt.Sprintf("%s/api/items/%s", bw.serverURL, itemID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+bw.token)
	req.Header.Set("Accept", "application/json")

	resp, err := bw.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to read item %s: %s", itemID, string(body))
	}

	var item BWItem
	if err := json.Unmarshal(body, &item); err != nil {
		return nil, err
	}
	return &item, nil
}

// putItem writes an item: PUT when it has an ID, POST to create otherwise. Returns the item ID the server reports (needed after a create).
func (bw *BWClient) putItem(ctx context.Context, item *BWItem) (string, error) {
	itemJSON, err := json.Marshal(item)
	if err != nil {
		return "", fmt.Errorf("failed to marshal item: %w", err)
	}

	var url, method string
	if item.ID != "" {
		url = fmt.Sprintf("%s/api/items/%s", bw.serverURL, item.ID)
		method = "PUT"
	} else {
		url = fmt.Sprintf("%s/api/items", bw.serverURL)
		method = "POST"
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewBuffer(itemJSON))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+bw.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := bw.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("failed to write item: %s", string(body))
	}

	var written BWItem
	if err := json.Unmarshal(body, &written); err != nil || written.ID == "" {
		return item.ID, nil
	}
	return written.ID, nil
}

// setBWField replaces the field with the same name, or appends it.
func setBWField(fields []BWField, field BWField) []BWField {
	for i := range fields {
		if fields[i].Name == field.Name {
			fields[i] = field
			return fields
		}
	}
	return append(fields, field)
}

// removeBWField drops every field carrying the given name.
func removeBWField(fields []BWField, name string) []BWField {
	kept := fields[:0]
	for _, f := range fields {
		if f.Name != name {
			kept = append(kept, f)
		}
	}
	return kept
}

func (bw *BWClient) GetCredentials(ctx context.Context, deviceID, vaultID, targetAdmin string) (*Credentials, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	res := &Credentials{OldLogin: targetAdmin}

	// Search for item by name
	url := fmt.Sprintf("%s/api/items?search=%s", bw.serverURL, deviceID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return res, err
	}

	req.Header.Set("Authorization", "Bearer "+bw.token)
	req.Header.Set("Accept", "application/json")

	resp, err := bw.httpClient.Do(req)
	if err != nil {
		return res, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return res, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return res, err
	}

	var items []BWItem
	if err := json.Unmarshal(body, &items); err != nil {
		return res, err
	}

	// Find matching item
	for _, item := range items {
		if item.Name == deviceID {
			res.ItemID = item.ID

			if item.Login.Username != "" {
				res.OldLogin = item.Login.Username
			}
			if item.Login.Password != "" {
				res.OldPassword = item.Login.Password
			}

			// Check for staged and legacy fields
			for _, field := range item.Fields {
				switch field.Name {
				case "pending_password":
					res.PendingPassword = field.Value
				case "legacy_login":
					res.LegacyLogin = field.Value
				case "legacy_password":
					res.LegacyPassword = field.Value
				}
			}

			break
		}
	}

	// Check for migration
	if res.OldLogin != "" && res.OldLogin != targetAdmin {
		res.IsMigration = true
	}

	return res, nil
}

// StagePendingPassword escrows the candidate password before the device is touched.
func (bw *BWClient) StagePendingPassword(ctx context.Context, creds *Credentials, deviceID, hostname, vaultID, newLogin, newPassword string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	pending := BWField{Name: "pending_password", Value: newPassword, Type: 1}

	if creds.ItemID == "" {
		item := &BWItem{
			Name:          deviceID,
			SecureNote:    BWSecureNote{Type: 0},
			CollectionIDs: []string{vaultID},
			Fields: []BWField{
				{Name: "hostname", Value: hostname, Type: 0},
				{Name: "serial", Value: deviceID, Type: 0},
				pending,
			},
		}
		id, err := bw.putItem(ctx, item)
		if err != nil {
			return fmt.Errorf("could not create the device item for staging: %w", err)
		}
		// Remember the ID so the confirming write updates this item instead of creating a second one.
		creds.ItemID = id
		return nil
	}

	item, err := bw.getItem(ctx, creds.ItemID)
	if err != nil {
		return fmt.Errorf("could not read the device item before staging: %w", err)
	}
	item.Fields = setBWField(item.Fields, pending)
	if _, err := bw.putItem(ctx, item); err != nil {
		return fmt.Errorf("could not stage the pending password: %w", err)
	}
	return nil
}

// ClearPendingPassword drops the staged value after a rotation the device policy refused.
func (bw *BWClient) ClearPendingPassword(ctx context.Context, creds *Credentials, vaultID string) error {
	if creds.ItemID == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	item, err := bw.getItem(ctx, creds.ItemID)
	if err != nil {
		return err
	}
	item.Fields = removeBWField(item.Fields, "pending_password")
	_, err = bw.putItem(ctx, item)
	return err
}

func (bw *BWClient) UpsertCredentials(ctx context.Context, creds *Credentials, deviceID, hostname, vaultID, newLogin, newPassword, tokenStatus string) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// The rebuilt field list intentionally carries no pending_password: committing the real password IS the confirming write.
	item := &BWItem{
		ID:   creds.ItemID,
		Name: deviceID,
		Login: BWLogin{
			Username: newLogin,
			Password: newPassword,
		},
		SecureNote:    BWSecureNote{Type: 0},
		CollectionIDs: []string{vaultID},
		Fields: []BWField{
			{Name: "hostname", Value: hostname, Type: 0},
			{Name: "serial", Value: deviceID, Type: 0},
			{Name: "secure_token", Value: tokenStatus, Type: 0},
			{Name: "updated_at", Value: time.Now().Format(time.RFC3339), Type: 0},
		},
	}

	// Add legacy credentials if migrating
	if creds.IsMigration && creds.OldLogin != "" {
		item.Fields = append(item.Fields,
			BWField{Name: "old_login", Value: creds.OldLogin, Type: 0},
			BWField{Name: "old_password", Value: creds.OldPassword, Type: 1},
		)
		if creds.LegacyLogin != "" {
			item.Fields = append(item.Fields,
				BWField{Name: "legacy_login", Value: creds.LegacyLogin, Type: 0},
				BWField{Name: "legacy_password", Value: creds.LegacyPassword, Type: 1},
			)
		}
	}

	if _, err := bw.putItem(ctx, item); err != nil {
		return fmt.Errorf("failed to upsert item: %w", err)
	}
	return nil
}

// Ensure interface compliance
var _ Client = (*BWClient)(nil)
