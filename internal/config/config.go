// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

package config

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	managedPreferencesDomain    = "io.github.golaps"
	serviceAccountKeychainLabel = "GoLAPS_Vault_Token"

	// secretsFromStdinFlag tells Load to read the vault token and the legacy password from stdin so neither secret appears in any process environment block.
	secretsFromStdinFlag = "--secrets-from-stdin"

	// Absolute Apple tool paths and a safe PATH for root child processes.
	defaultsBin = "/usr/bin/defaults"
	securityBin = "/usr/bin/security"
	toolPath    = "PATH=/usr/bin:/bin:/usr/sbin:/sbin"

	minPassLength = 16
	maxPassLength = 64

	defaultOnePasswordProbeURL = "https://my.1password.com"
)

var (
	unixAdminUserPattern    = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	windowsAdminUserPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,19}$`)
)

// reservedAdminUsers are accounts GoLAPS must never manage or recreate.
var reservedAdminUsers = map[string]bool{
	"root":               true,
	"laps-bridge":        true,
	"daemon":             true,
	"nobody":             true,
	"administrator":      true,
	"guest":              true,
	"defaultaccount":     true,
	"wdagutilityaccount": true,
}

type Config struct {
	AdminUser       string
	VaultType       string
	VaultID         string
	PassLength      int
	LegacyAdminPass string
	VaultToken      string
	ProbeURL        string

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

// sources holds the inputs of Load. Tests replace individual fields.
type sources struct {
	args          []string
	stdin         io.Reader
	getenv        func(string) string
	preference    func(ctx context.Context, key string) (string, bool)
	keychainToken func(ctx context.Context) (string, error)
}

func productionSources() sources {
	return sources{
		args:          os.Args,
		stdin:         os.Stdin,
		getenv:        os.Getenv,
		preference:    readManagedPreference,
		keychainToken: readKeychainToken,
	}
}

func Load(ctx context.Context) (*Config, error) {
	return load(ctx, productionSources())
}

func load(ctx context.Context, src sources) (*Config, error) {
	adminUser, adminSource := getConfigValue(ctx, src, "AdminUser", "LAPS_ADMIN_USER", "")
	if adminUser == "" {
		return nil, fmt.Errorf("AdminUser is required; set LAPS_ADMIN_USER or deploy the managed preference profile")
	}
	if err := validateAdminUser(adminUser); err != nil {
		return nil, err
	}
	log.Printf("[INFO] Loaded target AdminUser from %s: %s\n", adminSource, adminUser)

	vaultID, _ := getConfigValue(ctx, src, "VaultID", "LAPS_VAULT_ID", "")
	if vaultID == "" {
		return nil, fmt.Errorf("VaultID is required; set LAPS_VAULT_ID or deploy the managed preference profile")
	}

	vaultTypeRaw, _ := getConfigValue(ctx, src, "VaultType", "LAPS_VAULT_TYPE", "")
	vaultType := strings.ToLower(vaultTypeRaw)
	if vaultType == "" {
		return nil, fmt.Errorf("VaultType is required; set LAPS_VAULT_TYPE or deploy the managed preference profile")
	}

	token, legacyPass, err := readSecrets(ctx, src, vaultType)
	if err != nil {
		return nil, err
	}

	probeFallback := ""
	if vaultType == "onepassword" || vaultType == "1password" {
		probeFallback = defaultOnePasswordProbeURL
	}
	probeURL, _ := getConfigValue(ctx, src, "ProbeURL", "LAPS_PROBE_URL", probeFallback)

	cfg := &Config{
		AdminUser:       adminUser,
		VaultType:       vaultType,
		VaultID:         vaultID,
		PassLength:      clampPassLength(getConfigValueInt(ctx, src, "PasswordLength", "LAPS_PASSWORD_LENGTH", 18)),
		LegacyAdminPass: legacyPass,
		VaultToken:      token,
		ProbeURL:        probeURL,

		HashiCorpAddress: getEnv(src.getenv, "VAULT_ADDR", ""),
		HashiCorpPath:    getEnv(src.getenv, "LAPS_VAULT_PATH", "secret/data/laps"),

		BitwardenServerURL: getEnv(src.getenv, "BW_SERVER_URL", "https://api.bitwarden.com"),
		BitwardenAPIKey:    getEnv(src.getenv, "BWS_ACCESS_TOKEN", getEnv(src.getenv, "BW_API_KEY", token)),
		BitwardenOrgID:     getEnv(src.getenv, "BW_ORG_ID", ""),

		AWSRegion:  getEnv(src.getenv, "AWS_REGION", "us-east-1"),
		AWSProfile: getEnv(src.getenv, "AWS_PROFILE", ""),

		AzureTenantID:     getEnv(src.getenv, "AZURE_TENANT_ID", ""),
		AzureClientID:     getEnv(src.getenv, "AZURE_CLIENT_ID", ""),
		AzureClientSecret: getEnv(src.getenv, "AZURE_CLIENT_SECRET", ""),
		AzureVaultURL:     getEnv(src.getenv, "AZURE_VAULT_URL", ""),
	}

	return cfg, nil
}

func validateAdminUser(name string) error {
	return validateAdminUserForOS(name, runtime.GOOS)
}

func validateAdminUserForOS(name, goos string) error {
	pattern := unixAdminUserPattern
	if goos == "windows" {
		pattern = windowsAdminUserPattern
	}
	switch {
	case !pattern.MatchString(name):
		return fmt.Errorf("AdminUser %q is not a valid local account name (pattern %s)", name, pattern)
	case reservedAdminUsers[strings.ToLower(name)]:
		return fmt.Errorf("AdminUser %q is a reserved account that GoLAPS must never manage", name)
	case strings.HasPrefix(name, "_"):
		return fmt.Errorf("AdminUser %q is a system account (underscore prefix)", name)
	}
	return nil
}

func clampPassLength(n int) int {
	clamped := min(max(n, minPassLength), maxPassLength)
	if clamped != n {
		log.Printf("[WARNING] PasswordLength %d is outside %d..%d; using %d.\n", n, minPassLength, maxPassLength, clamped)
	}
	return clamped
}

// readSecrets reads the vault token and legacy password from stdin with --secrets-from-stdin, or from environment variables and System Keychain.
func readSecrets(ctx context.Context, src sources, vaultType string) (token, legacyPass string, err error) {
	if hasFlag(src.args, secretsFromStdinFlag) {
		r := bufio.NewReader(src.stdin)
		token = readLine(r)
		legacyPass = readLine(r)
		if token == "" && requiresVaultToken(vaultType) {
			return "", "", fmt.Errorf("vault token not found on stdin")
		}
		return token, legacyPass, nil
	}
	legacyPass = strings.TrimSpace(src.getenv("LEGACY_ADMIN_PASS"))
	token, err = getVaultToken(ctx, src, vaultType)
	if (err != nil || token == "") && requiresVaultToken(vaultType) {
		if err == nil {
			err = fmt.Errorf("vault token is empty")
		}
		return "", "", err
	}
	return token, legacyPass, nil
}

func hasFlag(args []string, flag string) bool {
	for _, a := range args[min(len(args), 1):] {
		if a == flag {
			return true
		}
	}
	return false
}

func readLine(r *bufio.Reader) string {
	line, _ := r.ReadString('\n')
	return strings.TrimSpace(strings.TrimPrefix(line, "\uFEFF"))
}

func getEnv(getenv func(string) string, key, fallback string) string {
	if val := strings.TrimSpace(getenv(key)); val != "" {
		return val
	}
	return fallback
}

func getConfigValue(ctx context.Context, src sources, key, envName, fallback string) (value, source string) {
	if envName != "" {
		if envVal := strings.TrimSpace(src.getenv(envName)); envVal != "" {
			return envVal, "env " + envName
		}
	}
	if val, fromProfile := src.preference(ctx, key); fromProfile {
		return val, "MDM Profile"
	}
	return fallback, "default"
}

func toolCommand(ctx context.Context, path string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{toolPath}
	return cmd
}

func readManagedPreference(ctx context.Context, key string) (string, bool) {
	if runtime.GOOS != "darwin" {
		return "", false
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := toolCommand(ctx, defaultsBin, "read", "/Library/Managed Preferences/"+managedPreferencesDomain, key)
	out, err := cmd.Output()
	if err != nil {
		return "", false
	}
	val := strings.TrimSpace(string(out))
	return val, val != ""
}

func getConfigValueInt(ctx context.Context, src sources, key, envName string, fallback int) int {
	if envName != "" {
		if envVal := strings.TrimSpace(src.getenv(envName)); envVal != "" {
			if val, err := strconv.Atoi(envVal); err == nil {
				return val
			}
		}
	}
	if valStr, ok := src.preference(ctx, key); ok {
		if val, err := strconv.Atoi(valStr); err == nil {
			return val
		}
	}
	return fallback
}

func getVaultToken(ctx context.Context, src sources, vaultType string) (string, error) {
	if envToken := strings.TrimSpace(src.getenv("LAPS_VAULT_TOKEN")); envToken != "" {
		return envToken, nil
	}
	if vaultType == "hashicorp" {
		if envToken := strings.TrimSpace(src.getenv("VAULT_TOKEN")); envToken != "" {
			return envToken, nil
		}
	}
	if envToken := strings.TrimSpace(src.getenv("OP_SERVICE_ACCOUNT_TOKEN")); envToken != "" {
		return envToken, nil
	}
	if runtime.GOOS == "darwin" {
		if token, err := src.keychainToken(ctx); err == nil && strings.TrimSpace(token) != "" {
			return strings.TrimSpace(token), nil
		}
	}
	return "", fmt.Errorf("vault token not found in LAPS_VAULT_TOKEN, provider-specific env vars, or System Keychain label %q", serviceAccountKeychainLabel)
}

func readKeychainToken(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := toolCommand(ctx, securityBin, "find-generic-password", "-l", serviceAccountKeychainLabel, "-w", "/Library/Keychains/System.keychain")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func requiresVaultToken(vaultType string) bool {
	switch vaultType {
	case "onepassword", "1password", "hashicorp":
		return true
	default:
		return false
	}
}
