// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

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

func TestGenerateLimitsSymbols(t *testing.T) {
	seenCounts := map[int]bool{}
	for i := 0; i < 1000; i++ {
		got, err := Generate(DefaultLength)
		if err != nil {
			t.Fatalf("Generate returned an error: %v", err)
		}
		count := 0
		for _, c := range got {
			if strings.ContainsRune(symbols, c) {
				count++
			}
		}
		if count < MinSymbols || count > MaxSymbols {
			t.Fatalf("password %q has %d symbols, want between %d and %d", got, count, MinSymbols, MaxSymbols)
		}
		seenCounts[count] = true
	}
	for n := MinSymbols; n <= MaxSymbols; n++ {
		if !seenCounts[n] {
			t.Errorf("no password with %d symbols in 1000 draws", n)
		}
	}
}

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
		{"aab8Xk3pQm9RtY2w", true},
		{"abc8Xk3pQm9RtY2w", true},
		{"cba8Xk3pQm9RtY2w", true},
		{"a1b2C3d4E5f6G7h8", false},
		{"X123kPmQ9RtY2wJn", true},
		{"aXbYcZ8k3p9q2w4e", false},
	}
	for _, tt := range tests {
		if got := violatesAllowSimple([]byte(tt.pw)); got != tt.want {
			t.Errorf("violatesAllowSimple(%q) = %v, want %v", tt.pw, got, tt.want)
		}
	}
}

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
