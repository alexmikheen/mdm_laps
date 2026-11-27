// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

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
	// The symbol set has no quotes, backticks, or backslashes so passwords pass safely through shell wrappers and OS tooling.
	symbols = "!@#$%^&*()-_=+[]{}|;:,.<>/?"

	alphanumerics = lower + upper + digits
	allChars      = alphanumerics + symbols

	// MinLength is the minimum accepted password length.
	MinLength = 16
	// DefaultLength applies when the caller asks for a length below MinLength.
	DefaultLength = 18

	// Limit symbols to 1-3 so admins can type passwords at the FileVault pre-boot screen.
	MinSymbols = 1
	MaxSymbols = 3
)

// Generate returns a random password with all four character classes that satisfies macOS allowSimple=false.
func Generate(length int) (string, error) {
	if length < MinLength {
		length = DefaultLength
	}

	for {
		result, err := draw(length)
		if err != nil {
			return "", err
		}

		hasLower := false
		hasUpper := false
		hasDigit := false
		for _, char := range result {
			if strings.ContainsRune(lower, rune(char)) {
				hasLower = true
			} else if strings.ContainsRune(upper, rune(char)) {
				hasUpper = true
			} else if strings.ContainsRune(digits, rune(char)) {
				hasDigit = true
			}
		}

		// MDM requireAlphanumeric rejects a password without all three classes with OD 5402.
		if hasLower && hasUpper && hasDigit && !violatesAllowSimple(result) {
			return string(result), nil
		}
	}
}

// draw fills the password with random alphanumerics, then replaces MinSymbols to MaxSymbols random positions with random symbols.
func draw(length int) ([]byte, error) {
	result := make([]byte, length)
	for i := range result {
		idx, err := randomIndex(len(alphanumerics))
		if err != nil {
			return nil, err
		}
		result[i] = alphanumerics[idx]
	}

	count, err := randomIndex(MaxSymbols - MinSymbols + 1)
	if err != nil {
		return nil, err
	}
	count += MinSymbols

	// Select distinct positions with a partial Fisher-Yates shuffle so two symbols never land on the same index.
	positions := make([]int, length)
	for i := range positions {
		positions[i] = i
	}
	for i := 0; i < count; i++ {
		j, err := randomIndex(length - i)
		if err != nil {
			return nil, err
		}
		positions[i], positions[i+j] = positions[i+j], positions[i]
		idx, err := randomIndex(len(symbols))
		if err != nil {
			return nil, err
		}
		result[positions[i]] = symbols[idx]
	}
	return result, nil
}

func randomIndex(n int) (int, error) {
	num, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0, fmt.Errorf("critical failure in random number generator: %w", err)
	}
	return int(num.Int64()), nil
}

// violatesAllowSimple checks macOS allowSimple=false (no doubled characters or 3-character runs).
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
