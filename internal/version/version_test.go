// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

package version

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestVersionConstantIsInjectable(t *testing.T) {
	data, err := os.ReadFile("version.go")
	if err != nil {
		t.Fatalf("read version.go: %v", err)
	}
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, `const Version = "`) {
			lines = append(lines, line)
		}
	}
	if len(lines) != 1 {
		t.Fatalf("version.go carries %d `const Version = \"` lines, want exactly one: %q", len(lines), lines)
	}
	m := regexp.MustCompile(`^const Version = "([^"]+)"`).FindStringSubmatch(lines[0])
	if len(m) < 2 {
		t.Fatalf("the Version line has no quoted value: %q", lines[0])
	}
	if m[1] != Version {
		t.Fatalf("the source line says %q, the compiled constant says %q", m[1], Version)
	}
	if !regexp.MustCompile(`^\d+\.\d+\.\d+(_\d+)?$`).MatchString(Version) {
		t.Fatalf("Version %q does not match MAJOR.MINOR.PATCH with an optional _N suffix", Version)
	}
}
