// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: GPL-3.0-or-later

package password

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
)

const (
	lower  = "abcdefghijklmnopqrstuvwxyz"
	upper  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits = "0123456789"
	// No quotes, backticks or backslashes: the generated password crosses AppleScript, shell wrappers and sysadminctl argument lists, and every one of those has its own quoting rules.
	symbols = "!@#$%^&*()-_=+[]{}|;:,.<>/?"

	allChars = lower + upper + digits + symbols

	// MinLength mirrors a 16+ character floor typical of corporate access-control policies.
	MinLength = 16
	// DefaultLength is used when the caller asks for anything shorter than MinLength.
	DefaultLength = 18
)

// Generate creates a cryptographically secure password of the specified length. It loops until the generated password contains at least one lowercase letter, one uppercase letter, and one digit to satisfy MDM complexity policies. An exhausted entropy source is returned as an error rather than ending the process: this runs after the vault has been read and the caller owns the shutdown path (log flushing, exit code), which a log.Fatal here used to bypass.
func Generate(length int) (string, error) {
	if length < MinLength {
		length = DefaultLength
	}

	// We use a loop to "generate and validate". It will keep generating new passwords in milliseconds until one perfectly matches the complexity rules.
	for {
		result := make([]byte, length)
		hasLower := false
		hasUpper := false
		hasDigit := false

		for i := range result {
			num, err := rand.Int(rand.Reader, big.NewInt(int64(len(allChars))))
			if err != nil {
				// Fail safely requirement
				return "", fmt.Errorf("critical failure in random number generator: %w", err)
			}
			char := allChars[num.Int64()]
			result[i] = char

			// Check which character pools were used
			if strings.ContainsRune(lower, rune(char)) {
				hasLower = true
			} else if strings.ContainsRune(upper, rune(char)) {
				hasUpper = true
			} else if strings.ContainsRune(digits, rune(char)) {
				hasDigit = true
			}
		}

		// MDM Policy check: Must contain alphanumeric characters. We enforce at least 1 lower, 1 upper, and 1 digit to be bulletproof.
		if hasLower && hasUpper && hasDigit && !violatesAllowSimple(result) {
			return string(result), nil
		}
		// If it fails the complexity check, the loop seamlessly restarts.
	}
}

// violatesAllowSimple reports whether the password would fail macOS's allowSimple=false policy check: two identical characters in a row, or three characters in an ascending/descending run. A passcode profile with allowSimple=false enforces it, and a purely random 18-char password carries a doubled character roughly a quarter of the time — observed in production, each such rotation came back as OD 5402 and, worse, read as auth-failed, which recreated a healthy admin.
func violatesAllowSimple(password []byte) bool {
	for i := 1; i < len(password); i++ {
		if password[i] == password[i-1] {
			return true
		}
	}
	for i := 2; i < len(password); i++ {
		ascending := password[i] == password[i-1]+1 && password[i-1] == password[i-2]+1
		descending := password[i] == password[i-1]-1 && password[i-1] == password[i-2]-1
		if ascending || descending {
			return true
		}
	}
	return false
}
