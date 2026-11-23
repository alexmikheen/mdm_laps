// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

//go:build darwin

package osmgmt

import "testing"

func FuzzParseDialogEvent(f *testing.F) {
	for _, seed := range []string{`{"event":"later"}`, `{"event":"timeout"}`, `{"event":"shown"}`, `{"event":"abr"}`, `{"event":"password","password":"secret"}`, `{}`, `not-json`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, line string) {
		ev, err := parseDialogEvent(line)
		if err == nil && ev.password != "" {
			t.Fatalf("parseDialogEvent returned a password on stdout: %+v", ev)
		}
	})
}

func FuzzParseMacSerial(f *testing.F) {
	for _, seed := range []string{`"IOPlatformSerialNumber" = "C02XG0FDJGH5"`, `"IOPlatformSerialNumber" = "Unknown"`, ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		_, _ = parseMacSerial(raw)
	})
}
