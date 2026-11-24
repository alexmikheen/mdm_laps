// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

package osmgmt

import (
	"strings"
	"testing"
)

func FuzzValidateLinuxSerial(f *testing.F) {
	for _, seed := range []string{
		"",
		"Unknown",
		"To be filled by O.E.M.",
		"O.E.M.",
		"Not Available",
		"Not Settable",
		"System Product Name",
		"Asset-1234567890",
		"XXXXXXXX",
		"123456789",
		"0123456789",
		"../secret",
		"a/b?c#d%20",
		"uninitialized",
		"00000000-0000-0000-0000-000000000000",
		"FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
		"PF2ABCDE",
		"4c8f2b1e9a7d4c3b8e1f0a2d5c6b7e8f",
		"bad\x00serial",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if got, err := validateLinuxSerial(raw); err == nil {
			if strings.ContainsAny(got, `/\?#%`) || strings.Contains(got, "..") {
				t.Fatalf("accepted unsafe path serial %q", got)
			}
		}
	})
}

func FuzzValidateChpasswdInput(f *testing.F) {
	f.Add("lapsadmin", "Sup3rS3cret!")
	f.Add("root", "Sup3rS3cret!")
	f.Add("-o", "Sup3rS3cret!")
	f.Add("--help", "Sup3rS3cret!")
	f.Add("0", "Sup3rS3cret!")
	f.Add("laps:admin", "pass")
	f.Add("lapsadmin", "line1\nroot:evil")
	f.Add("lapsadmin", "line1\rroot:evil")
	f.Add("", "")

	f.Fuzz(func(t *testing.T, user, pass string) {
		if err := validateChpasswdInput(user, pass); err == nil {
			if user == "" || user == "root" || pass == "" {
				t.Fatalf("accepted forbidden user or empty password: %q / %q", user, pass)
			}
			if !linuxUsernameRe.MatchString(user) {
				t.Fatalf("accepted invalid username %q", user)
			}
			if strings.ContainsAny(pass, "\r\n") {
				t.Fatalf("accepted password with line break %q", pass)
			}
		}
	})
}

func FuzzParseGetentGroupLine(f *testing.F) {
	f.Add("sudo:x:27:alice", "sudo")
	f.Add("wheel:x:10:", "wheel")
	f.Add("malformed", "sudo")
	f.Add("", "")

	f.Fuzz(func(t *testing.T, line, group string) {
		_ = parseGetentGroupLine(line, group)
	})
}
