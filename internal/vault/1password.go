// internal/vault/1password.go
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

	"golaps/internal/version"
)

const (
	// 5 attempts with jittered backoff: a fleet-wide rollout can stampede the vault with concurrent writes ("data conflict occurred on the server"), and synchronized 2s/4s retries just collide again — observed in production, where a device exhausting all attempts on its final write leaves the vault stale until the next run.
	opAttempts    = 5
	opRetryDelay  = 2 * time.Second
	opCallTimeout = 30 * time.Second
)

type OPClient struct {
	client *onepassword.Client
}

// withRetry re-runs a 1Password call that failed for a transient reason. Each attempt gets its own timeout; the caller's context still bounds the whole thing, so a run
func withRetry[T any](ctx context.Context, what string, call func(context.Context) (T, error)) (T, error) {
	var zero T
	var lastErr error

	for attempt := 1; attempt <= opAttempts; attempt++ {
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
			break // the run budget is gone; more attempts cannot help
		}
		if attempt < opAttempts {
			log.Printf("[WARNING] %s failed (attempt %d/%d): %v. Retrying...\n", what, attempt, opAttempts, err)
			// Random jitter breaks fleet-wide retry lockstep — without it every device that conflicted retries on the same 2s/4s grid and conflicts again.
			select {
			case <-ctx.Done():
			case <-time.After(time.Duration(attempt)*opRetryDelay + time.Duration(rand.Intn(3000))*time.Millisecond):
			}
		}
	}

	return zero, fmt.Errorf("%s failed after %d attempts: %w", what, opAttempts, lastErr)
}

// pickNewestMatch returns the ID of the most recently updated item whose title matches deviceID, and how many items matched in total.
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

func New1PasswordClient(ctx context.Context, token string) (*OPClient, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	c, err := onepassword.NewClient(ctx,
		onepassword.WithServiceAccountToken(token),
		onepassword.WithIntegrationInfo("golaps", version.Version),
	)
	if err != nil {
		return nil, err
	}
	return &OPClient{client: c}, nil
}

func (op *OPClient) GetCredentials(ctx context.Context, deviceID, vaultID, targetAdmin string) (*Credentials, error) {
	res := &Credentials{OldLogin: targetAdmin} // Default until the item says otherwise

	items, err := withRetry(ctx, "listing the LAPS vault", func(c context.Context) ([]onepassword.ItemOverview, error) {
		return op.client.Items().List(c, vaultID)
	})
	if err != nil {
		return res, err
	}

	id, matches := pickNewestMatch(items, deviceID)
	res.ItemID = id
	if matches > 1 {
		log.Printf("[WARNING] %d 1Password items share the serial %s. Using the most recently updated one (%s); the rest are stale duplicates and need cleaning up — reading one of those would feed an old password back as the current one.\n", matches, deviceID, id)
	}

	if res.ItemID != "" {
		existingItem, err := withRetry(ctx, "reading the device's 1Password item", func(c context.Context) (onepassword.Item, error) {
			return op.client.Items().Get(c, vaultID, res.ItemID)
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

// StagePendingPassword writes the candidate password to the item before the device is touched.
func (op *OPClient) StagePendingPassword(ctx context.Context, creds *Credentials, deviceID, hostname, vaultID, newLogin, newPassword string) error {
	pending := onepassword.ItemField{
		ID:        PendingPasswordFieldID,
		Title:     "PENDING password " + newLogin + " (unconfirmed)",
		FieldType: onepassword.ItemFieldTypeConcealed,
		Value:     newPassword,
	}

	if creds.ItemID == "" {
		created, err := withRetry(ctx, "creating the device's 1Password item", func(c context.Context) (onepassword.Item, error) {
			return op.client.Items().Create(c, onepassword.ItemCreateParams{
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
		// Remember the ID so the confirming write updates this item instead of creating a second one.
		creds.ItemID = created.ID
		return nil
	}

	// The Get lives INSIDE the retry: a timed-out Put can still land server-side, and re-sending the same stale item then fails every remaining attempt with "The submitted item is not up to date" (observed in production). Refetching per attempt keeps the write idempotent.
	if _, err := withRetry(ctx, "staging the pending password", func(c context.Context) (onepassword.Item, error) {
		item, err := op.client.Items().Get(c, vaultID, creds.ItemID)
		if err != nil {
			return item, err
		}
		item.Fields = setField(item.Fields, pending)
		return op.client.Items().Put(c, item)
	}); err != nil {
		return fmt.Errorf("could not stage the pending password on item %s: %w", creds.ItemID, err)
	}
	return nil
}

// ClearPendingPassword drops the staged field after a rotation whose new password the device policy refused — that value was never applied, and left in place it poisons the next run's passForReset fallback. Read-modify-write inside one retry, same as the other writers.
func (op *OPClient) ClearPendingPassword(ctx context.Context, creds *Credentials, vaultID string) error {
	if creds.ItemID == "" {
		return nil
	}
	if _, err := withRetry(ctx, "clearing the refused pending password", func(c context.Context) (onepassword.Item, error) {
		item, err := op.client.Items().Get(c, vaultID, creds.ItemID)
		if err != nil {
			return item, err
		}
		item.Fields = removeField(item.Fields, PendingPasswordFieldID)
		return op.client.Items().Put(c, item)
	}); err != nil {
		return fmt.Errorf("could not clear the pending password on item %s: %w", creds.ItemID, err)
	}
	return nil
}

func (op *OPClient) UpsertCredentials(ctx context.Context, creds *Credentials, deviceID, hostname, vaultID, newLogin, newPassword, tokenStatus string) error {
	if creds.ItemID != "" {
		// Read-modify-write as ONE retried unit. The Get error must not be discarded (a zero-value Item's empty Category produced the fleet's "An unsupported item category was specified" failures), and the Get must repeat per attempt: a timed-out Put can still land server-side, after which re-sending the stale item version fails every retry with "The submitted item is not up to date" (observed in production).
		if _, err := withRetry(ctx, "writing the rotated password", func(c context.Context) (onepassword.Item, error) {
			existingItem, err := op.client.Items().Get(c, vaultID, creds.ItemID)
			if err != nil {
				return existingItem, err
			}
			existingItem.Fields = applyRotatedFields(existingItem.Fields, creds, newLogin, newPassword, tokenStatus, hostname)
			return op.client.Items().Put(c, existingItem)
		}); err != nil {
			return fmt.Errorf("could not update 1Password item %s: %w", creds.ItemID, err)
		}
		return nil
	}

	// Create New (only reachable if staging was skipped)
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
	if _, err := withRetry(ctx, "creating the device's 1Password item", func(c context.Context) (onepassword.Item, error) {
		return op.client.Items().Create(c, itemParams)
	}); err != nil {
		return fmt.Errorf("could not create the 1Password item for %s: %w", deviceID, err)
	}
	return nil
}

// applyRotatedFields writes the rotation result onto the item's fields: legacy credentials are preserved once during a migration, and the staged pending copy is dropped now that the real password field carries it.
func applyRotatedFields(fields []onepassword.ItemField, creds *Credentials, newLogin, newPassword, tokenStatus, hostname string) []onepassword.ItemField {
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
		ID: "field_secure_token", Title: "Provide Secure token",
		FieldType: onepassword.ItemFieldTypeText, Value: tokenStatus,
	})
	fields = setField(fields, onepassword.ItemField{
		ID: "field_hostname", Title: "Host name",
		FieldType: onepassword.ItemFieldTypeText, Value: hostname,
	})
	return removeField(fields, PendingPasswordFieldID)
}

// IsNetworkError reports whether a vault failure is connectivity to 1Password rather than anything LAPS can fix on the device. The SDK runs its HTTP stack inside wazero, so wrapped sentinel errors rarely survive and the strings observed in production logs are matched too.
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

// setField replaces the field with the same ID, or appends it when the item has none.
func setField(fields []onepassword.ItemField, field onepassword.ItemField) []onepassword.ItemField {
	for i := range fields {
		if fields[i].ID == field.ID {
			// Keep the section the field already lives in, so an operator's manual tidying survives.
			field.SectionID = fields[i].SectionID
			fields[i] = field
			return fields
		}
	}
	return append(fields, field)
}

// setFieldIfAbsent adds the field only when the item does not already carry that ID.
func setFieldIfAbsent(fields []onepassword.ItemField, field onepassword.ItemField) []onepassword.ItemField {
	for i := range fields {
		if fields[i].ID == field.ID {
			return fields
		}
	}
	return append(fields, field)
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
