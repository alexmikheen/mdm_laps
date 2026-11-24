// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

package osmgmt

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"unicode"
)

const linuxChildPath = "PATH=/usr/sbin:/usr/bin:/sbin:/bin"

var linuxUsernameRe = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}\$?$`)

var linuxSerialPaths = []string{
	"/sys/class/dmi/id/product_serial",
	"/sys/class/dmi/id/board_serial",
	"/sys/class/dmi/id/product_uuid",
	"/etc/machine-id",
}

var linuxToolDirs = []string{
	"/usr/sbin",
	"/sbin",
	"/usr/bin",
	"/bin",
}

var linuxAdminGroups = []string{
	"sudo",
	"wheel",
}

var linuxSerialPlaceholders = []string{
	"Unknown",
	"To be filled by O.E.M.",
	"Default string",
	"0",
	"System Serial Number",
	"Chassis Serial Number",
	"Board Serial Number",
	"Base Board Serial Number",
	"Not Specified",
	"Not Applicable",
	"Not Available",
	"None",
	"N/A",
	"Invalid",
	"Empty",
	"O.E.M.",
	"uninitialized",
}

func linuxChildEnv() []string {
	return []string{linuxChildPath}
}

// validateLinuxSerial rejects empty values, control characters, and OEM placeholders.
func validateLinuxSerial(raw string) (string, error) {
	serial := strings.TrimSpace(raw)
	if serial == "" {
		return "", errors.New("serial is empty")
	}
	for _, r := range serial {
		if unicode.IsControl(r) {
			return "", fmt.Errorf("serial contains control characters: %q", serial)
		}
	}
	if strings.Trim(serial, "0-") == "" || strings.Trim(strings.ToUpper(serial), "F-") == "" {
		return "", fmt.Errorf("serial is an all-zero or all-F placeholder: %q", serial)
	}
	for _, placeholder := range linuxSerialPlaceholders {
		if strings.EqualFold(serial, placeholder) {
			return "", fmt.Errorf("serial is an OEM placeholder: %q", serial)
		}
	}
	return serial, nil
}

// selectLinuxSerial reads candidate paths in order and returns the first valid serial.
func selectLinuxSerial(readFile func(string) ([]byte, error), paths []string) (string, error) {
	for _, path := range paths {
		data, err := readFile(path)
		if err != nil {
			continue
		}
		if serial, err := validateLinuxSerial(string(data)); err == nil {
			return serial, nil
		}
	}
	return "", errors.New("could not find a valid system serial or machine ID")
}

// validateChpasswdInput rejects invalid usernames, root, and delimiters that corrupt chpasswd stdin lines.
func validateChpasswdInput(user, newPass string) error {
	if user == "" {
		return errors.New("username is empty")
	}
	if user == "root" {
		return errors.New("refusing to manage the root account")
	}
	if !linuxUsernameRe.MatchString(user) {
		return fmt.Errorf("username %q is not a valid Linux account name", user)
	}
	if newPass == "" {
		return errors.New("new password is empty")
	}
	if strings.ContainsAny(newPass, "\r\n") {
		return errors.New("new password must not contain line breaks")
	}
	return nil
}

// scrubSecret replaces every occurrence of secret in text with [REDACTED].
func scrubSecret(text, secret string) string {
	if secret == "" {
		return text
	}
	return strings.ReplaceAll(text, secret, "[REDACTED]")
}

// resolveLinuxTool locates an executable binary inside the fixed system directories.
func resolveLinuxTool(name string, stat func(string) (os.FileInfo, error)) (string, error) {
	if name == "" || strings.Contains(name, "/") {
		return "", fmt.Errorf("invalid tool name %q", name)
	}
	for _, dir := range linuxToolDirs {
		path := dir + "/" + name
		info, err := stat(path)
		if err != nil {
			continue
		}
		if !info.IsDir() && info.Mode()&0o111 != 0 {
			return path, nil
		}
	}
	return "", fmt.Errorf("required tool %q was not found in system directories", name)
}

// selectLinuxShell returns /bin/bash when present and executable, or /bin/sh otherwise.
func selectLinuxShell(stat func(string) (os.FileInfo, error)) string {
	if info, err := stat("/bin/bash"); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
		return "/bin/bash"
	}
	return "/bin/sh"
}

// parseGetentGroupLine checks whether a getent group output line matches groupName.
func parseGetentGroupLine(line, groupName string) bool {
	if groupName == "" {
		return false
	}
	firstLine, _, _ := strings.Cut(strings.TrimSpace(line), "\n")
	name, _, ok := strings.Cut(firstLine, ":")
	return ok && name == groupName
}

// detectLinuxAdminGroup returns the first existing admin group from linuxAdminGroups.
func detectLinuxAdminGroup(lookup func(group string) (string, error)) (string, error) {
	for _, group := range linuxAdminGroups {
		out, err := lookup(group)
		if err != nil {
			continue
		}
		if parseGetentGroupLine(out, group) {
			return group, nil
		}
	}
	return "", fmt.Errorf("no supported admin group (%s) exists on this system", strings.Join(linuxAdminGroups, ", "))
}
