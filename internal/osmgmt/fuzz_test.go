// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

package osmgmt

import "testing"

func FuzzValidateWindowsSerial(f *testing.F) {
	for _, seed := range []string{"", "Unknown", "To be filled by O.E.M.", "00000000-0000-0000-0000-000000000000", "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF", "PF2ABCDE", "7967FCD2-0CE4-4C0E-AE6C-F66536181D11", "bad\x00serial"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		_, _ = validateWindowsSerial(raw)
	})
}
