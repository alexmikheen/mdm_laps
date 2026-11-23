// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

package vault

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"strings"
	"time"

	"github.com/1password/onepassword-sdk-go"
)

const (
	opAttempts    = 5
	opRetryDelay  = 2 * time.Second
	opCallTimeout = 30 * time.Second
)

type OPClient struct {
	// Keep client alive so its GC finalizer does not release the WASM client ID while ItemsAPI runs.
	client *onepassword.Client
	items  onepassword.ItemsAPI
}

// retryBackoff is the pause before the next attempt. Random jitter breaks fleet-wide retry lockstep. Tests replace it with a zero pause.
var retryBackoff = func(attempt int) time.Duration {
	return time.Duration(attempt)*opRetryDelay + time.Duration(rand.Intn(3000))*time.Millisecond
}

func withRetry[T any](ctx context.Context, what string, call func(context.Context) (T, error)) (T, error) {
	var zero T
	var lastErr error

	attemptsRun := 0
	for attempt := 1; attempt <= opAttempts; attempt++ {
		attemptsRun = attempt
		attemptCtx, cancel := context.WithTimeout(ctx, opCallTimeout)
		result, err := call(attemptCtx)
		cancel()

		if err == nil {
			if attempt > 1 {
				log.Printf("[INFO] %s succeeded on attempt %d.\n", what, attempt)
			}
			return result, nil
		}
		lastErr = err

		if ctx.Err() != nil {
			break
		}
		if attempt < opAttempts {
			log.Printf("[WARNING] %s failed (attempt %d/%d): %v. Retrying...\n", what, attempt, opAttempts, err)
			select {
			case <-ctx.Done():
				return zero, fmt.Errorf("%s failed after %d attempts: %w", what, attemptsRun, lastErr)
			case <-time.After(retryBackoff(attempt)):
			}
		}
	}

	return zero, fmt.Errorf("%s failed after %d attempts: %w", what, attemptsRun, lastErr)
}

func pickNewestMatch(items []onepassword.ItemOverview, deviceID string) (id string, matches int) {
	best := -1
	for i := range items {
		if !strings.EqualFold(strings.TrimSpace(items[i].Title), deviceID) {
			continue
		}
		matches++
		if best == -1 || items[i].UpdatedAt.After(items[best].UpdatedAt) {
			best = i
		}
	}
	if best == -1 {
		return "", 0
	}
	return items[best].ID, matches
}

var lapsVersion = "unknown"

// SetIntegrationVersion records the binary version for the 1Password integration info. Call before New1PasswordClient.
func SetIntegrationVersion(version string) { lapsVersion = version }

// IntegrationVersion returns the version string reported to 1Password.
func IntegrationVersion() string { return "v" + lapsVersion }

func New1PasswordClient(ctx context.Context, token string) (*OPClient, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	c, err := onepassword.NewClient(ctx,
		onepassword.WithServiceAccountToken(token),
		onepassword.WithIntegrationInfo("GoLAPS", IntegrationVersion()),
	)
	if err != nil {
		return nil, err
	}
	return newOPClient(c), nil
}

func newOPClient(c *onepassword.Client) *OPClient {
	return &OPClient{client: c, items: c.Items()}
}

func (op *OPClient) GetCredentials(ctx context.Context, deviceID, vaultID, targetAdmin string) (*Credentials, error) {
	res := &Credentials{OldLogin: targetAdmin}

	items, err := withRetry(ctx, "listing the LAPS vault", func(c context.Context) ([]onepassword.ItemOverview, error) {
		return op.items.List(c, vaultID)
	})
	if err != nil {
		return res, err
	}

	id, matches := pickNewestMatch(items, deviceID)
	res.ItemID = id
	if matches > 1 {
		log.Printf("[WARNING] %d 1Password items share the serial %s. Using the most recently updated one (%s); the rest are stale duplicates and need cleaning up.\n", matches, deviceID, id)
	}

	if res.ItemID != "" {
		existingItem, err := withRetry(ctx, "reading the device's 1Password item", func(c context.Context) (onepassword.Item, error) {
			return op.items.Get(c, vaultID, res.ItemID)
		})
		if err != nil {
			return res, fmt.Errorf("could not read 1Password item %s: %w", res.ItemID, err)
		}
		for _, field := range existingItem.Fields {
			if field.ID == "field_password" && field.Value != "" {
				res.OldPassword = field.Value
			}
			if field.ID == "field_login" {
				res.OldLogin = field.Value
			}
			if field.ID == PendingPasswordFieldID {
				res.PendingPassword = field.Value
			}
			if field.ID == PreviousPendingFieldID {
				res.PreviousPendingPassword = field.Value
			}
			if field.ID == BridgePasswordFieldID {
				res.BridgePassword = field.Value
			}
			if strings.HasPrefix(field.ID, "legacy_login") {
				res.LegacyLogin = field.Value
			}
			if strings.HasPrefix(field.ID, "legacy_password") {
				res.LegacyPassword = field.Value
			}
		}
		if res.OldLogin != "" && res.OldLogin != targetAdmin {
			res.IsMigration = true
		}
	}
	return res, nil
}

func (op *OPClient) StagePendingPassword(ctx context.Context, creds *Credentials, deviceID, hostname, vaultID, newLogin, newPassword string) error {
	pending := onepassword.ItemField{
		ID:        PendingPasswordFieldID,
		Title:     "PENDING password " + newLogin + " (unconfirmed)",
		FieldType: onepassword.ItemFieldTypeConcealed,
		Value:     newPassword,
	}

	if creds.ItemID == "" {
		adopted := false
		created, err := withRetry(ctx, "creating the device's 1Password item", func(c context.Context) (onepassword.Item, error) {
			existing, err := op.items.List(c, vaultID)
			if err != nil {
				return onepassword.Item{}, err
			}
			if id, _ := pickNewestMatch(existing, deviceID); id != "" {
				log.Printf("[INFO] The 1Password item for %s exists now (%s); adopting it instead of creating a second one.\n", deviceID, id)
				adopted = true
				return onepassword.Item{ID: id}, nil
			}
			return op.items.Create(c, onepassword.ItemCreateParams{
				VaultID:  vaultID,
				Title:    deviceID,
				Category: onepassword.ItemCategorySecureNote,
				Tags:     []string{"LAPS", "MDM_Automated"},
				Fields: []onepassword.ItemField{
					{ID: "field_hostname", Title: "Host name", FieldType: onepassword.ItemFieldTypeText, Value: hostname},
					{ID: "field_serial", Title: "Serial Number", FieldType: onepassword.ItemFieldTypeText, Value: deviceID},
					pending,
				},
			})
		})
		if err != nil {
			return fmt.Errorf("could not create the 1Password item for %s: %w", deviceID, err)
		}
		creds.ItemID = created.ID
		if !adopted {
			return nil
		}
	}

	if _, err := withRetry(ctx, "staging the pending password", func(c context.Context) (onepassword.Item, error) {
		item, err := op.items.Get(c, vaultID, creds.ItemID)
		if err != nil {
			return item, err
		}
		if old, ok := fieldValueOf(item.Fields, PendingPasswordFieldID); ok && old != "" && old != newPassword {
			item.Fields = setField(item.Fields, onepassword.ItemField{
				ID:        PreviousPendingFieldID,
				Title:     "PREVIOUS pending password " + newLogin + " (unconfirmed)",
				FieldType: onepassword.ItemFieldTypeConcealed,
				Value:     old,
			})
		}
		item.Fields = setField(item.Fields, pending)
		return op.items.Put(c, item)
	}); err != nil {
		return fmt.Errorf("could not stage the pending password on item %s: %w", creds.ItemID, err)
	}
	return nil
}

func (op *OPClient) ClearPendingPassword(ctx context.Context, creds *Credentials, vaultID string) error {
	if creds.ItemID == "" {
		return nil
	}
	if _, err := withRetry(ctx, "clearing the refused pending password", func(c context.Context) (onepassword.Item, error) {
		item, err := op.items.Get(c, vaultID, creds.ItemID)
		if err != nil {
			return item, err
		}
		item.Fields = removeField(item.Fields, PendingPasswordFieldID)
		if previous, ok := fieldValueOf(item.Fields, PreviousPendingFieldID); ok && previous != "" {
			item.Fields = setField(item.Fields, onepassword.ItemField{
				ID:        PendingPasswordFieldID,
				Title:     "PENDING password (unconfirmed, restored)",
				FieldType: onepassword.ItemFieldTypeConcealed,
				Value:     previous,
			})
			item.Fields = removeField(item.Fields, PreviousPendingFieldID)
		}
		return op.items.Put(c, item)
	}); err != nil {
		return fmt.Errorf("could not clear the pending password on item %s: %w", creds.ItemID, err)
	}
	return nil
}

func (op *OPClient) StageBridgePassword(ctx context.Context, creds *Credentials, vaultID, password string) error {
	if creds.ItemID == "" {
		return errors.New("the device has no 1Password item yet; the bridge password has nowhere to go")
	}
	field := onepassword.ItemField{
		ID:        BridgePasswordFieldID,
		Title:     "bridge password (LAPS heal)",
		FieldType: onepassword.ItemFieldTypeConcealed,
		Value:     password,
	}
	if _, err := withRetry(ctx, "escrowing the bridge password", func(c context.Context) (onepassword.Item, error) {
		item, err := op.items.Get(c, vaultID, creds.ItemID)
		if err != nil {
			return item, err
		}
		item.Fields = setField(item.Fields, field)
		return op.items.Put(c, item)
	}); err != nil {
		return fmt.Errorf("could not escrow the bridge password on item %s: %w", creds.ItemID, err)
	}
	creds.BridgePassword = password
	return nil
}

func (op *OPClient) ClearBridgePassword(ctx context.Context, creds *Credentials, vaultID string) error {
	if creds.ItemID == "" {
		return nil
	}
	if _, err := withRetry(ctx, "clearing the bridge password", func(c context.Context) (onepassword.Item, error) {
		item, err := op.items.Get(c, vaultID, creds.ItemID)
		if err != nil {
			return item, err
		}
		item.Fields = removeField(item.Fields, BridgePasswordFieldID)
		return op.items.Put(c, item)
	}); err != nil {
		return fmt.Errorf("could not clear the bridge password on item %s: %w", creds.ItemID, err)
	}
	creds.BridgePassword = ""
	return nil
}

func (op *OPClient) ConfirmLivePassword(ctx context.Context, creds *Credentials, deviceID, hostname, vaultID, login, live string) error {
	if creds.ItemID == "" {
		return fmt.Errorf("the device %s has no 1Password item; a live password cannot be confirmed on it", deviceID)
	}
	if _, err := withRetry(ctx, "confirming the live password", func(c context.Context) (onepassword.Item, error) {
		item, err := op.items.Get(c, vaultID, creds.ItemID)
		if err != nil {
			return item, err
		}
		item.Fields = applyConfirmedFields(item.Fields, creds, login, live, hostname)
		return op.items.Put(c, item)
	}); err != nil {
		return fmt.Errorf("could not confirm the live password on item %s: %w", creds.ItemID, err)
	}
	creds.recordConfirmed(login, live)
	return nil
}

func (op *OPClient) UpsertCredentials(ctx context.Context, creds *Credentials, deviceID, hostname, vaultID, newLogin, newPassword, tokenStatus string) error {
	if creds.ItemID != "" {
		if _, err := withRetry(ctx, "writing the rotated password", func(c context.Context) (onepassword.Item, error) {
			existingItem, err := op.items.Get(c, vaultID, creds.ItemID)
			if err != nil {
				return existingItem, err
			}
			existingItem.Fields = applyRotatedFields(existingItem.Fields, creds, newLogin, newPassword, tokenStatus, hostname)
			return op.items.Put(c, existingItem)
		}); err != nil {
			return fmt.Errorf("could not update 1Password item %s: %w", creds.ItemID, err)
		}
		return nil
	}

	itemParams := onepassword.ItemCreateParams{
		VaultID: vaultID, Title: deviceID, Category: onepassword.ItemCategorySecureNote, Tags: []string{"LAPS", "MDM_Automated"},
		Fields: []onepassword.ItemField{
			{ID: "field_hostname", Title: "Host name", FieldType: onepassword.ItemFieldTypeText, Value: hostname},
			{ID: "field_serial", Title: "Serial Number", FieldType: onepassword.ItemFieldTypeText, Value: deviceID},
			{ID: "field_login", Title: "user login", FieldType: onepassword.ItemFieldTypeText, Value: newLogin},
			{ID: "field_password", Title: "password " + newLogin, FieldType: onepassword.ItemFieldTypeConcealed, Value: newPassword},
			{ID: "field_secure_token", Title: "Provide Secure token", FieldType: onepassword.ItemFieldTypeText, Value: tokenStatus},
		},
	}
	adopted := false
	created, err := withRetry(ctx, "creating the device's 1Password item", func(c context.Context) (onepassword.Item, error) {
		existing, err := op.items.List(c, vaultID)
		if err != nil {
			return onepassword.Item{}, err
		}
		if id, _ := pickNewestMatch(existing, deviceID); id != "" {
			adopted = true
			return onepassword.Item{ID: id}, nil
		}
		return op.items.Create(c, itemParams)
	})
	if err != nil {
		return fmt.Errorf("could not create the 1Password item for %s: %w", deviceID, err)
	}
	creds.ItemID = created.ID
	if adopted {
		return op.UpsertCredentials(ctx, creds, deviceID, hostname, vaultID, newLogin, newPassword, tokenStatus)
	}
	return nil
}

func applyRotatedFields(fields []onepassword.ItemField, creds *Credentials, newLogin, newPassword, tokenStatus, hostname string) []onepassword.ItemField {
	fields = applyConfirmedFields(fields, creds, newLogin, newPassword, hostname)
	return setField(fields, onepassword.ItemField{
		ID: "field_secure_token", Title: "Provide Secure token",
		FieldType: onepassword.ItemFieldTypeText, Value: tokenStatus,
	})
}

func applyConfirmedFields(fields []onepassword.ItemField, creds *Credentials, newLogin, newPassword, hostname string) []onepassword.ItemField {
	if creds.IsMigration {
		fields = setFieldIfAbsent(fields, onepassword.ItemField{
			ID: "legacy_login_" + creds.OldLogin, Title: "legacy login " + creds.OldLogin,
			FieldType: onepassword.ItemFieldTypeText, Value: creds.OldLogin,
		})
		fields = setFieldIfAbsent(fields, onepassword.ItemField{
			ID: "legacy_password_" + creds.OldLogin, Title: "legacy password " + creds.OldLogin,
			FieldType: onepassword.ItemFieldTypeConcealed, Value: creds.OldPassword,
		})
	}
	fields = setField(fields, onepassword.ItemField{
		ID: "field_password", Title: "password " + newLogin,
		FieldType: onepassword.ItemFieldTypeConcealed, Value: newPassword,
	})
	fields = setField(fields, onepassword.ItemField{
		ID: "field_login", Title: "user login",
		FieldType: onepassword.ItemFieldTypeText, Value: newLogin,
	})
	fields = setField(fields, onepassword.ItemField{
		ID: "field_hostname", Title: "Host name",
		FieldType: onepassword.ItemFieldTypeText, Value: hostname,
	})
	fields = removeField(fields, PendingPasswordFieldID)
	return removeField(fields, PreviousPendingFieldID)
}

func IsNetworkError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	msg := err.Error()
	for _, marker := range []string{"context deadline exceeded", "connection reset", "connection refused", "no such host", "i/o timeout", "operation timed out", "no route to host", "network is unreachable", "TLS handshake timeout"} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

func setField(fields []onepassword.ItemField, field onepassword.ItemField) []onepassword.ItemField {
	for i := range fields {
		if fields[i].ID == field.ID {
			field.SectionID = fields[i].SectionID
			fields[i] = field
			return fields
		}
	}
	return append(fields, field)
}

func setFieldIfAbsent(fields []onepassword.ItemField, field onepassword.ItemField) []onepassword.ItemField {
	for i := range fields {
		if fields[i].ID == field.ID {
			return fields
		}
	}
	return append(fields, field)
}

func fieldValueOf(fields []onepassword.ItemField, id string) (string, bool) {
	for i := range fields {
		if fields[i].ID == id {
			return fields[i].Value, true
		}
	}
	return "", false
}

func removeField(fields []onepassword.ItemField, id string) []onepassword.ItemField {
	kept := fields[:0]
	for _, f := range fields {
		if f.ID != id {
			kept = append(kept, f)
		}
	}
	return kept
}
