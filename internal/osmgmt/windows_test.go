// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

package osmgmt

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestPowerShellEnvIsBuiltFromScratch(t *testing.T) {
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "must-not-leak")
	t.Setenv("LEGACY_ADMIN_PASS", "must-not-leak-either")

	env := powerShellEnv(`C:\Windows\`, `C:\Users\x\Temp`, "LAPS_TARGET_USER=localadmin")

	allowed := map[string]bool{"SystemRoot": true, "windir": true, "PATH": true, "TEMP": true, "TMP": true, "LAPS_TARGET_USER": true}
	seen := map[string]string{}
	for _, kv := range env {
		key, value, ok := strings.Cut(kv, "=")
		if !ok {
			t.Fatalf("malformed entry %q", kv)
		}
		if !allowed[key] {
			t.Fatalf("the child environment carries %q, which is not on the allow list: %v", key, env)
		}
		if strings.Contains(value, "must-not-leak") {
			t.Fatalf("a parent secret reached the child environment: %v", env)
		}
		seen[key] = value
	}
	for key := range allowed {
		if _, ok := seen[key]; !ok {
			t.Fatalf("the child environment lacks %s: %v", key, env)
		}
	}
	if seen["SystemRoot"] != `C:\Windows` || seen["windir"] != `C:\Windows` {
		t.Fatalf("SystemRoot/windir = %q/%q, want C:\\Windows without the trailing backslash", seen["SystemRoot"], seen["windir"])
	}
	if seen["PATH"] != `C:\Windows\System32;C:\Windows\System32\WindowsPowerShell\v1.0` {
		t.Fatalf("PATH = %q, want System32 and the PowerShell folder only", seen["PATH"])
	}
	if seen["TEMP"] != `C:\Users\x\Temp` || seen["TMP"] != `C:\Users\x\Temp` {
		t.Fatalf("TEMP/TMP = %q/%q, want the given temp folder", seen["TEMP"], seen["TMP"])
	}
}

func TestPowerShellEnvTempFallback(t *testing.T) {
	for _, kv := range powerShellEnv(`C:\Windows`, "") {
		if strings.HasPrefix(kv, "TEMP=") && kv != `TEMP=C:\Windows\Temp` {
			t.Fatalf("TEMP fallback = %q, want C:\\Windows\\Temp", kv)
		}
	}
}

func TestPowerShellPathIsAbsoluteUnderSystemRoot(t *testing.T) {
	want := `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
	for _, root := range []string{`C:\Windows`, `C:\Windows\`} {
		if got := powerShellPath(root); got != want {
			t.Fatalf("powerShellPath(%q) = %q, want %q", root, got, want)
		}
	}
}

func TestEnsureAccountScriptReadsThePasswordFromStdin(t *testing.T) {
	if strings.Contains(ensureAccountScript, "LAPS_NEW_PASS") {
		t.Fatal("the script still reads the password from the environment")
	}
	if !strings.Contains(ensureAccountScript, "[Console]::In.ReadLine()") {
		t.Fatal("the script does not read the password from stdin")
	}
	if !strings.Contains(ensureAccountScript, "Write-Output '"+resultMarker+"'") {
		t.Fatalf("the script does not print the result marker %q as its last step", resultMarker)
	}
	trimmed := strings.TrimSpace(ensureAccountScript)
	if !strings.HasSuffix(trimmed, "Write-Output '"+resultMarker+"'") {
		t.Fatal("the result marker is not the last statement of the script")
	}
	if strings.Contains(ensureAccountScript, "-Member $account.SID") {
		t.Fatal("Add-LocalGroupMember -Member rejects SecurityIdentifier objects; pass $account instead")
	}
	if !strings.Contains(ensureAccountScript, "Add-LocalGroupMember -SID 'S-1-5-32-544' -Member $account") {
		t.Fatal("the script must pass the LocalUser object $account to Add-LocalGroupMember")
	}
	if !strings.Contains(ensureAccountScript, "$ProgressPreference = 'SilentlyContinue'") || !strings.Contains(serialScript, "$ProgressPreference = 'SilentlyContinue'") {
		t.Fatal("PowerShell scripts must suppress CLIXML progress output on stderr")
	}
}

func TestScriptReportsSuccessNeedsTheExactMarkerLine(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want bool
	}{
		{"marker only", "LAPS_RESULT=OK", true},
		{"marker last with CRLF", "PASSWORD_ROTATED\r\nALREADY_ADMIN\r\nLAPS_RESULT=OK\r\n", true},
		{"marker last with trailing blank lines", "ACCOUNT_CREATED\nLAPS_RESULT=OK\n\n  \n", true},
		{"bare OK", "PASSWORD_ROTATED\nOK", false},
		{"NOT_OK", "NOT_OK", false},
		{"marker inside an error text", "LAPS_RESULT=OK was expected but Set-LocalUser failed", false},
		{"marker followed by an error", "LAPS_RESULT=OK\nException: access denied", false},
		{"marker with a prefix", "xLAPS_RESULT=OK", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := scriptReportsSuccess(tc.out); got != tc.want {
				t.Fatalf("scriptReportsSuccess(%q) = %v, want %v", tc.out, got, tc.want)
			}
		})
	}
}

func TestValidateWindowsSerialRejectsPlaceholders(t *testing.T) {
	for _, bad := range []string{"", "   ", "Unknown", "unknown", "To be filled by O.E.M.", "TO BE FILLED BY O.E.M.", "Default string", "0", "00000000-0000-0000-0000-000000000000", "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF", "System Serial Number", "Not Specified", "not specified"} {
		if got, err := validateWindowsSerial(bad); err == nil {
			t.Fatalf("validateWindowsSerial(%q) = %q, want an error", bad, got)
		}
	}
	for _, good := range []string{"PF2ABCDE", " 5CD1234XYZ ", "VMware-56 4d 12 ab", "7967FCD2-0CE4-4C0E-AE6C-F66536181D11"} {
		got, err := validateWindowsSerial(good)
		if err != nil {
			t.Fatalf("validateWindowsSerial(%q): %v", good, err)
		}
		if got != strings.TrimSpace(good) {
			t.Fatalf("validateWindowsSerial(%q) = %q, want the trimmed value", good, got)
		}
	}
}

func TestVersionConstantExists(t *testing.T) {
	re := regexp.MustCompile(`const Version = "([^"]+)"`)
	data, err := os.ReadFile(filepath.Join("..", "version", "version.go"))
	if err != nil {
		t.Fatalf("read version.go: %v", err)
	}
	if !re.Match(data) {
		t.Fatalf("internal/version/version.go carries no Version constant")
	}
}

func TestPickWindowsSerialFallsBackPastAPlaceholder(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    string
		wantErr string
	}{
		{"BIOS value wins", "BIOS=TESTSER0001\r\nCSP=TESTSER0002\r\n", "TESTSER0001", ""},
		{"blank BIOS value", "BIOS=\r\nCSP=TESTSER0002\r\n", "TESTSER0002", ""},
		{"placeholder BIOS value", "BIOS=Default string\r\nCSP=TESTSER0002\r\n", "TESTSER0002", ""},
		{"O.E.M. placeholder BIOS value", "BIOS=To be filled by O.E.M.\nCSP=TESTSER0002", "TESTSER0002", ""},
		{"UUID fallback when BIOS and CSP are placeholders", "BIOS=Default string\r\nCSP=To be filled by O.E.M.\r\nUUID=7967FCD2-0CE4-4C0E-AE6C-F66536181D11\r\n", "7967FCD2-0CE4-4C0E-AE6C-F66536181D11", ""},
		{"all three are placeholders", "BIOS=Default string\r\nCSP=To be filled by O.E.M.\r\nUUID=FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF\r\n", "", `placeholder serial "Default string"`},
		{"both are placeholders", "BIOS=Default string\r\nCSP=To be filled by O.E.M.\r\n", "", `placeholder serial "Default string"`},
		{"both are blank", "BIOS=\r\nCSP=\r\n", "", "no serial"},
		{"CLIXML noise before the tagged lines", "#< CLIXML\r\n<Objs Version=\"1.1.0.1\"><Obj S=\"progress\"/></Objs>\r\nBIOS=TESTSER0001\r\nCSP=TESTSER0002\r\n", "TESTSER0001", ""},
		{"noise only", "#< CLIXML\r\n<Objs Version=\"1.1.0.1\"></Objs>\r\n", "", "tagged"},
		{"empty output", "", "", "tagged"},
		{"untagged serial is ignored", "TESTSER0001\r\n", "", "tagged"},
		{"valid BIOS and a different valid CSP", "BIOS=TESTSER0001\nCSP=TESTSER0099\n", "TESTSER0001", ""},
		{"spaces around the tagged line", "  BIOS=TESTSER0001  \r\n", "TESTSER0001", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := pickWindowsSerial(tc.raw)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("pickWindowsSerial(%q) = %q, %v, want an error with %q", tc.raw, got, err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("pickWindowsSerial(%q) = %q, %v, want %q", tc.raw, got, err, tc.want)
			}
		})
	}
}

func TestSerialScriptPrintsBothFirmwareValues(t *testing.T) {
	for _, class := range []string{"Win32_BIOS", "Win32_ComputerSystemProduct"} {
		if !strings.Contains(serialScript, class) {
			t.Errorf("the serial script does not read %s", class)
		}
	}
	for _, want := range []string{"$ProgressPreference = 'SilentlyContinue'", "BIOS=", "CSP=", "UUID="} {
		if !strings.Contains(serialScript, want) {
			t.Errorf("the serial script lacks %s", want)
		}
	}
	if strings.Index(serialScript, "BIOS=") > strings.Index(serialScript, "CSP=") || strings.Index(serialScript, "CSP=") > strings.Index(serialScript, "UUID=") {
		t.Error("the tagged lines must appear in BIOS, CSP, UUID order")
	}
	if strings.Contains(serialScript, "IsNullOrWhiteSpace") {
		t.Error("the script picks the serial itself, so a placeholder never reaches the Go check")
	}
}
