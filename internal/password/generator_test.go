// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: GPL-3.0-or-later

package password

import (
	"strings"
	"testing"
)

func TestGenerateLength(t *testing.T) {
	tests := []struct {
		name  string
		asked int
		want  int
	}{
		{name: "policy minimum is honoured", asked: 16, want: 16},
		{name: "longer request is respected", asked: 32, want: 32},
		{name: "below the policy floor falls back to the safe default", asked: 8, want: DefaultLength},
		{name: "zero falls back to the safe default", asked: 0, want: DefaultLength},
		{name: "negative falls back to the safe default", asked: -5, want: DefaultLength},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Generate(tt.asked)
			if err != nil {
				t.Fatalf("Generate(%d) returned an error: %v", tt.asked, err)
			}
			if len(got) != tt.want {
				t.Errorf("Generate(%d) produced %d characters, want %d", tt.asked, len(got), tt.want)
			}
		})
	}
}

// The MDM requireAlphanumeric policy rejects a password without all three classes with Code=5402, so this property is the whole reason the generator loops.
func TestGenerateAlwaysMeetsComplexityPolicy(t *testing.T) {
	for i := 0; i < 200; i++ {
		got, err := Generate(MinLength)
		if err != nil {
			t.Fatalf("Generate returned an error: %v", err)
		}
		if !strings.ContainsAny(got, lower) {
			t.Fatalf("password %q has no lowercase character", got)
		}
		if !strings.ContainsAny(got, upper) {
			t.Fatalf("password %q has no uppercase character", got)
		}
		if !strings.ContainsAny(got, digits) {
			t.Fatalf("password %q has no digit", got)
		}
	}
}

// The password crosses AppleScript string literals, shell wrappers and sysadminctl argument lists. A quote, backtick or backslash slipping into the charset would break one of them in a way that only shows up on the device that drew the unlucky character.
func TestGenerateUsesOnlySafeCharacters(t *testing.T) {
	const forbidden = "\"'`\\ \t\n"

	for i := 0; i < 200; i++ {
		got, err := Generate(24)
		if err != nil {
			t.Fatalf("Generate returned an error: %v", err)
		}
		if idx := strings.IndexAny(got, forbidden); idx >= 0 {
			t.Fatalf("password %q contains unsafe character %q", got, got[idx])
		}
		for _, c := range got {
			if !strings.ContainsRune(allChars, c) {
				t.Fatalf("password %q contains %q, which is outside the declared alphabet", got, c)
			}
		}
	}
}

func TestGenerateDoesNotRepeat(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		got, err := Generate(MinLength)
		if err != nil {
			t.Fatalf("Generate returned an error: %v", err)
		}
		if seen[got] {
			t.Fatalf("Generate produced the same password twice: %q", got)
		}
		seen[got] = true
	}
}

func TestViolatesAllowSimple(t *testing.T) {
	tests := []struct {
		pw   string
		want bool
	}{
		{"aab8Xk3pQm9RtY2w", true},  // doubled character
		{"abc8Xk3pQm9RtY2w", true},  // ascending run
		{"cba8Xk3pQm9RtY2w", true},  // descending run
		{"a1b2C3d4E5f6G7h8", false}, // clean
		{"X123kPmQ9RtY2wJn", true},  // ascending digits
		{"aXbYcZ8k3p9q2w4e", false}, // letters interleaved, no runs
	}
	for _, tt := range tests {
		if got := violatesAllowSimple([]byte(tt.pw)); got != tt.want {
			t.Errorf("violatesAllowSimple(%q) = %v, want %v", tt.pw, got, tt.want)
		}
	}
}

// A passcode profile with allowSimple=false evaluates every rotated password; a single violating sample means roughly 1 in 4 rotations on affected Macs fails with OD 5402 and recreates a healthy admin.
func TestGenerateSatisfiesAllowSimple(t *testing.T) {
	for i := 0; i < 500; i++ {
		pw, err := Generate(DefaultLength)
		if err != nil {
			t.Fatalf("Generate failed: %v", err)
		}
		if len(pw) != DefaultLength {
			t.Fatalf("length = %d, want %d", len(pw), DefaultLength)
		}
		if violatesAllowSimple([]byte(pw)) {
			t.Fatalf("generated password violates allowSimple: %q", pw)
		}
	}
}
