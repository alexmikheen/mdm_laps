// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

//go:build !cgo || !bitwarden_sdk

package vault

import "fmt"

// NewBitwardenClient fails closed without -tags=bitwarden_sdk to avoid passing passwords to an external CLI.
func NewBitwardenClient(serverURL, accessToken, orgID string) (*BWClient, error) {
	return nil, fmt.Errorf("Bitwarden Secrets Manager requires a build with -tags=bitwarden_sdk (CGO_ENABLED=1) so secrets are never passed in process arguments")
}
