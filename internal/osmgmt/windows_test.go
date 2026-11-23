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
	for _, bad := range []string{"", "   ", "Unknown", "unknown", "To be filled by O.E.M.", "TO BE FILLED BY O.E.M.", "Default string", "0", "System Serial Number", "Not Specified", "not specified"} {
		if got, err := validateWindowsSerial(bad); err == nil {
			t.Fatalf("validateWindowsSerial(%q) = %q, want an error", bad, got)
		}
	}
	for _, good := range []string{"PF2ABCDE", " 5CD1234XYZ ", "VMware-56 4d 12 ab"} {
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
