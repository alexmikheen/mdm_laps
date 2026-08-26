package config

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	managedPreferencesDomain    = "io.github.golaps"
	serviceAccountKeychainLabel = "GoLAPS_Vault_Token"
)

type Config struct {
	AdminUser       string
	VaultType       string
	VaultID         string
	PassLength      int
	LegacyAdminPass string
	VaultToken      string

	HashiCorpAddress string
	HashiCorpPath    string

	BitwardenServerURL string
	BitwardenAPIKey    string
	BitwardenOrgID     string

	AWSRegion  string
	AWSProfile string

	AzureTenantID     string
	AzureClientID     string
	AzureClientSecret string
	AzureVaultURL     string
}

func Load(ctx context.Context) (*Config, error) {
	adminUser, adminSource := getConfigValue(ctx, "AdminUser", "LAPS_ADMIN_USER", "")
	if adminUser == "" {
		return nil, fmt.Errorf("AdminUser is required; set LAPS_ADMIN_USER or deploy the managed preference profile")
	}
	log.Printf("[INFO] Loaded target AdminUser from %s: %s\n", adminSource, adminUser)

	vaultID, _ := getConfigValue(ctx, "VaultID", "LAPS_VAULT_ID", "")
	if vaultID == "" {
		return nil, fmt.Errorf("VaultID is required; set LAPS_VAULT_ID or deploy the managed preference profile")
	}

	vaultTypeRaw, _ := getConfigValue(ctx, "VaultType", "LAPS_VAULT_TYPE", "")
	vaultType := strings.ToLower(vaultTypeRaw)
	if vaultType == "" {
		return nil, fmt.Errorf("VaultType is required; set LAPS_VAULT_TYPE or deploy the managed preference profile")
	}

	rawLegacyPass := os.Getenv("LEGACY_ADMIN_PASS")
	cleanLegacyPass := strings.TrimSpace(rawLegacyPass)

	cfg := &Config{
		AdminUser:       adminUser,
		VaultType:       vaultType,
		VaultID:         vaultID,
		PassLength:      getConfigValueInt(ctx, "PasswordLength", "LAPS_PASSWORD_LENGTH", 18),
		LegacyAdminPass: cleanLegacyPass,

		HashiCorpAddress: getEnv("VAULT_ADDR", ""),
		HashiCorpPath:    getEnv("LAPS_VAULT_PATH", "secret/data/laps"),

		BitwardenServerURL: getEnv("BW_SERVER_URL", "https://api.bitwarden.com"),
		BitwardenAPIKey:    getEnv("BW_API_KEY", ""),
		BitwardenOrgID:     getEnv("BW_ORG_ID", ""),

		AWSRegion:  getEnv("AWS_REGION", "us-east-1"),
		AWSProfile: getEnv("AWS_PROFILE", ""),

		AzureTenantID:     getEnv("AZURE_TENANT_ID", ""),
		AzureClientID:     getEnv("AZURE_CLIENT_ID", ""),
		AzureClientSecret: getEnv("AZURE_CLIENT_SECRET", ""),
		AzureVaultURL:     getEnv("AZURE_VAULT_URL", ""),
	}

	token, err := getVaultToken(ctx, vaultType)
	if err != nil && requiresVaultToken(vaultType) {
		return nil, err
	}
	cfg.VaultToken = token

	return cfg, nil
}

func getEnv(key, fallback string) string {
	if val := strings.TrimSpace(os.Getenv(key)); val != "" {
		return val
	}
	return fallback
}

// getConfigValue resolves a setting env-first, then from the managed preference profile. The source string in the return lets the caller say WHERE a value came from: a value that merely EQUALS the default is otherwise indistinguishable from a missing profile, which makes "config read failed" warnings fire on devices where the profile was fine all along.
func getConfigValue(ctx context.Context, key, envName, fallback string) (value, source string) {
	if envName != "" {
		if envVal := strings.TrimSpace(os.Getenv(envName)); envVal != "" {
			return envVal, "env " + envName
		}
	}
	if val, fromProfile := readManagedPreference(ctx, key); fromProfile {
		return val, "MDM Profile"
	}
	return fallback, "default"
}

// readManagedPreference returns the managed value and whether the profile actually supplied it.
func readManagedPreference(ctx context.Context, key string) (string, bool) {
	if runtime.GOOS != "darwin" {
		return "", false
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "defaults", "read", "/Library/Managed Preferences/"+managedPreferencesDomain, key)
	out, err := cmd.Output()
	if err != nil {
		return "", false
	}
	val := strings.TrimSpace(string(out))
	return val, val != ""
}

func getConfigValueInt(ctx context.Context, key, envName string, fallback int) int {
	if envName != "" {
		if envVal := strings.TrimSpace(os.Getenv(envName)); envVal != "" {
			if val, err := strconv.Atoi(envVal); err == nil {
				return val
			}
		}
	}

	if runtime.GOOS == "darwin" {
		if valStr, ok := readManagedPreference(ctx, key); ok {
			if val, err := strconv.Atoi(valStr); err == nil {
				return val
			}
		}
	}
	return fallback
}

func getVaultToken(ctx context.Context, vaultType string) (string, error) {
	if envToken := os.Getenv("LAPS_VAULT_TOKEN"); envToken != "" {
		return strings.TrimSpace(envToken), nil
	}

	if vaultType == "hashicorp" {
		if envToken := os.Getenv("VAULT_TOKEN"); envToken != "" {
			return strings.TrimSpace(envToken), nil
		}
	}

	if envToken := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN"); envToken != "" {
		return strings.TrimSpace(envToken), nil
	}
	if runtime.GOOS == "darwin" {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "security", "find-generic-password", "-l", serviceAccountKeychainLabel, "-w", "/Library/Keychains/System.keychain")
		if output, err := cmd.Output(); err == nil {
			return strings.TrimSpace(string(output)), nil
		}
	}
	return "", fmt.Errorf("vault token not found in LAPS_VAULT_TOKEN, provider-specific env vars, or System Keychain label %q", serviceAccountKeychainLabel)
}

func requiresVaultToken(vaultType string) bool {
	switch vaultType {
	case "onepassword", "1password", "hashicorp":
		return true
	default:
		return false
	}
}
