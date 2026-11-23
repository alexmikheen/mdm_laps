// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

package config

import (
	"context"
	"strings"
	"testing"
)

func baseTestSources(env map[string]string) sources {
	return sources{
		args:   []string{"golaps"},
		stdin:  strings.NewReader(""),
		getenv: func(k string) string { return env[k] },
		preference: func(context.Context, string) (string, bool) {
			return "", false
		},
		keychainToken: func(context.Context) (string, error) {
			return "", nil
		},
	}
}

func TestLoadFromEnv(t *testing.T) {
	src := baseTestSources(map[string]string{
		"LAPS_ADMIN_USER":      "localadmin",
		"LAPS_VAULT_ID":        "vault-123",
		"LAPS_VAULT_TYPE":      "onepassword",
		"LAPS_VAULT_TOKEN":     "  tok_abc  ",
		"LEGACY_ADMIN_PASS":    "  legacy123  ",
		"LAPS_PASSWORD_LENGTH": "22",
	})
	cfg, err := load(context.Background(), src)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if cfg.AdminUser != "localadmin" {
		t.Errorf("AdminUser = %q, want localadmin", cfg.AdminUser)
	}
	if cfg.VaultToken != "tok_abc" {
		t.Errorf("VaultToken = %q, want tok_abc", cfg.VaultToken)
	}
	if cfg.LegacyAdminPass != "legacy123" {
		t.Errorf("LegacyAdminPass = %q, want legacy123", cfg.LegacyAdminPass)
	}
	if cfg.PassLength != 22 {
		t.Errorf("PassLength = %d, want 22", cfg.PassLength)
	}
	if cfg.ProbeURL != defaultOnePasswordProbeURL {
		t.Errorf("ProbeURL = %q, want %q", cfg.ProbeURL, defaultOnePasswordProbeURL)
	}
}

func TestLoadSecretsFromStdin(t *testing.T) {
	src := baseTestSources(map[string]string{
		"LAPS_ADMIN_USER": "localadmin",
		"LAPS_VAULT_ID":   "vault-123",
		"LAPS_VAULT_TYPE": "onepassword",
	})
	src.args = []string{"golaps", "--secrets-from-stdin"}
	src.stdin = strings.NewReader("  stdin_token \n  stdin_legacy \n")

	cfg, err := load(context.Background(), src)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if cfg.VaultToken != "stdin_token" {
		t.Errorf("VaultToken = %q, want stdin_token", cfg.VaultToken)
	}
	if cfg.LegacyAdminPass != "stdin_legacy" {
		t.Errorf("LegacyAdminPass = %q, want stdin_legacy", cfg.LegacyAdminPass)
	}
}

func TestValidateAdminUserRejectsReservedAndInvalid(t *testing.T) {
	badUnix := []string{"root", "laps-bridge", "daemon", "nobody", "_spotlight", "BadUpper", "bad space", ""}
	for _, name := range badUnix {
		if err := validateAdminUserForOS(name, "darwin"); err == nil {
			t.Errorf("validateAdminUserForOS(%q, darwin) succeeded, want error", name)
		}
	}
	goodUnix := []string{"localadmin", "it_admin", "laps-admin01"}
	for _, name := range goodUnix {
		if err := validateAdminUserForOS(name, "darwin"); err != nil {
			t.Errorf("validateAdminUserForOS(%q, darwin) failed: %v", name, err)
		}
	}

	badWin := []string{"Administrator", "Guest", "WDAGUtilityAccount", "laps-bridge", "bad space", "TooLongWindowsAccountName", ""}
	for _, name := range badWin {
		if err := validateAdminUserForOS(name, "windows"); err == nil {
			t.Errorf("validateAdminUserForOS(%q, windows) succeeded, want error", name)
		}
	}
	goodWin := []string{"LocalAdmin", "LAPSAdmin", "it.admin-01"}
	for _, name := range goodWin {
		if err := validateAdminUserForOS(name, "windows"); err != nil {
			t.Errorf("validateAdminUserForOS(%q, windows) failed: %v", name, err)
		}
	}
}

func TestClampPassLength(t *testing.T) {
	if got := clampPassLength(8); got != minPassLength {
		t.Errorf("clampPassLength(8) = %d, want %d", got, minPassLength)
	}
	if got := clampPassLength(128); got != maxPassLength {
		t.Errorf("clampPassLength(128) = %d, want %d", got, maxPassLength)
	}
	if got := clampPassLength(24); got != 24 {
		t.Errorf("clampPassLength(24) = %d, want 24", got)
	}
}
