// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

package config

import (
	"context"
	"strings"
	"testing"
)

func FuzzValidateAdminUser(f *testing.F) {
	for _, seed := range []string{"localadmin", "LocalAdmin", "root", "Administrator", "_spotlight", "laps-bridge", "", "a b", "it_admin-01"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, name string) {
		_ = validateAdminUserForOS(name, "darwin")
		_ = validateAdminUserForOS(name, "windows")
	})
}

func FuzzReadSecrets(f *testing.F) {
	f.Add("\uFEFFtok_123\r\nlegacy_456\r\n")
	f.Add("")
	f.Add("\n\n\n")
	f.Fuzz(func(t *testing.T, input string) {
		src := baseTestSources(map[string]string{})
		src.args = []string{"golaps", "--secrets-from-stdin"}
		src.stdin = strings.NewReader(input)
		_, _, _ = readSecrets(context.Background(), src, "hashicorp")
	})
}
