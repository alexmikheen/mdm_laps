// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

package osmgmt

import (
	"errors"
	"fmt"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

const (
	linuxChildPath     = "PATH=/usr/sbin:/usr/bin:/sbin:/bin"
	linuxPasswdPath    = "/etc/passwd"
	linuxLoginDefsPath = "/etc/login.defs"
	defaultLinuxUIDMin = 1000
	linuxManagedGECOS  = "GoLAPS managed"
)

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
	"Default",
	"0",
	"System Serial Number",
	"System Product Name",
	"Chassis Serial Number",
	"Chassis Asset Tag",
	"Board Serial Number",
	"Base Board Serial Number",
	"Not Specified",
	"Not Settable",
	"Not Applicable",
	"Not Available",
	"None",
	"N/A",
	"Invalid",
	"Empty",
	"O.E.M.",
	"uninitialized",
}

type linuxPasswdEntry struct {
	Name  string
	UID   int
	GID   int
	GECOS string
	Home  string
	Shell string
}

type linuxFileOwner interface {
	OwnerUID() uint32
}

type linuxToolFS struct {
	stat         func(string) (os.FileInfo, error)
	lstat        func(string) (os.FileInfo, error)
	evalSymlinks func(string) (string, error)
	fileOwner    func(os.FileInfo) (uint32, bool)
}

func linuxChildEnv() []string {
	return []string{linuxChildPath}
}

func normalizeSerialToken(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == '-' || r == '_' || unicode.IsSpace(r) {
			continue
		}
		b.WriteRune(unicode.ToUpper(r))
	}
	return b.String()
}

func isRepeatedSerial(norm string) bool {
	if norm == "" {
		return true
	}
	var first rune
	for i, r := range norm {
		if i == 0 {
			first = r
			continue
		}
		if r != first {
			return false
		}
	}
	return true
}

func isSimpleSequenceSerial(norm string) bool {
	if len(norm) < 4 {
		return false
	}
	allDigits := true
	asc := true
	desc := true
	wrapAsc := true
	wrapDesc := true
	for i := 0; i < len(norm); i++ {
		if norm[i] < '0' || norm[i] > '9' {
			allDigits = false
		}
		if i == 0 {
			continue
		}
		prev := norm[i-1]
		curr := norm[i]
		if curr != prev+1 {
			asc = false
		}
		if prev != curr+1 {
			desc = false
		}
		if allDigits {
			if (curr-'0') != (prev-'0'+1)%10 {
				wrapAsc = false
			}
			if (prev-'0') != (curr-'0'+1)%10 {
				wrapDesc = false
			}
		}
	}
	return asc || desc || (allDigits && (wrapAsc || wrapDesc))
}

// validateLinuxSerial rejects empty values, control or path-unsafe characters, repeated patterns, simple sequences, and OEM placeholders.
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
	if strings.ContainsAny(serial, `/\?#%`) || strings.Contains(serial, "..") || serial == "." {
		return "", fmt.Errorf("serial contains unsafe path or URL characters: %q", serial)
	}
	if strings.Trim(serial, "0-") == "" || strings.Trim(strings.ToUpper(serial), "F-") == "" {
		return "", fmt.Errorf("serial is an all-zero or all-F placeholder: %q", serial)
	}
	norm := normalizeSerialToken(serial)
	if isRepeatedSerial(norm) {
		return "", fmt.Errorf("serial is a repeated-character placeholder: %q", serial)
	}
	if isSimpleSequenceSerial(norm) {
		return "", fmt.Errorf("serial is a simple sequence placeholder: %q", serial)
	}
	if strings.HasPrefix(strings.ToLower(serial), "asset-") {
		return "", fmt.Errorf("serial has an OEM Asset- placeholder prefix: %q", serial)
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
	for _, p := range paths {
		data, err := readFile(p)
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

// parsePasswdLine parses one colon-delimited passwd entry.
func parsePasswdLine(line string) (linuxPasswdEntry, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return linuxPasswdEntry{}, false
	}
	parts := strings.Split(trimmed, ":")
	if len(parts) != 7 || parts[0] == "" {
		return linuxPasswdEntry{}, false
	}
	uid, err := strconv.Atoi(parts[2])
	if err != nil || uid < 0 {
		return linuxPasswdEntry{}, false
	}
	gid, err := strconv.Atoi(parts[3])
	if err != nil || gid < 0 {
		return linuxPasswdEntry{}, false
	}
	return linuxPasswdEntry{
		Name:  parts[0],
		UID:   uid,
		GID:   gid,
		GECOS: parts[4],
		Home:  parts[5],
		Shell: parts[6],
	}, true
}

// lookupLocalPasswd finds a user entry in /etc/passwd content.
func lookupLocalPasswd(content, user string) (linuxPasswdEntry, bool) {
	if user == "" {
		return linuxPasswdEntry{}, false
	}
	for _, line := range strings.Split(content, "\n") {
		entry, ok := parsePasswdLine(line)
		if ok && entry.Name == user {
			return entry, true
		}
	}
	return linuxPasswdEntry{}, false
}

// parseLoginDefsUIDMin reads UID_MIN from /etc/login.defs content, falling back to 1000.
func parseLoginDefsUIDMin(content string) int {
	uidMin := defaultLinuxUIDMin
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 2 && fields[0] == "UID_MIN" {
			if v, err := strconv.Atoi(fields[1]); err == nil && v > 0 {
				uidMin = v
			}
		}
	}
	return uidMin
}

// validateManagedLocalAccount verifies that an existing local user is safe for GoLAPS to manage.
func validateManagedLocalAccount(entry linuxPasswdEntry, uidMin int) error {
	if entry.UID == 0 {
		return fmt.Errorf("refusing to manage uid 0 account %q", entry.Name)
	}
	if uidMin <= 0 {
		uidMin = defaultLinuxUIDMin
	}
	if entry.UID < uidMin {
		return fmt.Errorf("refusing to manage system account %q (uid %d < UID_MIN %d)", entry.Name, entry.UID, uidMin)
	}
	if !strings.Contains(entry.GECOS, linuxManagedGECOS) {
		return fmt.Errorf("refusing to manage existing local account %q without %q GECOS marker", entry.Name, linuxManagedGECOS)
	}
	return nil
}

func resolveFileOwner(info os.FileInfo, hook func(os.FileInfo) (uint32, bool)) (uint32, bool) {
	if hook != nil {
		return hook(info)
	}
	if owner, ok := info.(linuxFileOwner); ok {
		return owner.OwnerUID(), true
	}
	return 0, false
}

func checkTrustedLinuxEntry(entryPath string, fs linuxToolFS, wantDir bool) error {
	info, err := fs.lstat(entryPath)
	if err != nil {
		return fmt.Errorf("%s cannot be checked: %w", entryPath, err)
	}
	mode := info.Mode()
	if mode&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symbolic link", entryPath)
	}
	if wantDir {
		if !mode.IsDir() {
			return fmt.Errorf("%s is not a directory", entryPath)
		}
	} else {
		if !mode.IsRegular() {
			return fmt.Errorf("%s is not a regular file", entryPath)
		}
		if mode.Perm()&0o111 == 0 {
			return fmt.Errorf("%s is not executable", entryPath)
		}
	}
	uid, ok := resolveFileOwner(info, fs.fileOwner)
	if !ok {
		return fmt.Errorf("%s has no readable owner", entryPath)
	}
	if uid != 0 {
		return fmt.Errorf("%s is owned by uid %d, not root", entryPath, uid)
	}
	if perm := mode.Perm(); perm&0o022 != 0 {
		return fmt.Errorf("%s is writable by group or other (mode %04o)", entryPath, perm)
	}
	return nil
}

// resolveLinuxTool locates an executable binary in system directories and verifies root ownership and permissions after resolving symlinks.
func resolveLinuxTool(name string, fs linuxToolFS) (string, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return "", fmt.Errorf("invalid tool name %q", name)
	}
	if fs.stat == nil || fs.lstat == nil || fs.evalSymlinks == nil {
		return "", errors.New("tool verification hooks are not configured")
	}
	for _, dir := range linuxToolDirs {
		candidate := dir + "/" + name
		info, err := fs.stat(candidate)
		if err != nil {
			continue
		}
		if info.IsDir() || info.Mode().Perm()&0o111 == 0 {
			continue
		}
		resolved, err := fs.evalSymlinks(candidate)
		if err != nil {
			return "", fmt.Errorf("could not resolve %s: %w", candidate, err)
		}
		resolved = path.Clean(resolved)
		if !strings.HasPrefix(resolved, "/") {
			return "", fmt.Errorf("resolved tool path %q is not absolute", resolved)
		}
		if err := checkTrustedLinuxEntry(resolved, fs, false); err != nil {
			return "", err
		}
		for parent := path.Dir(resolved); ; parent = path.Dir(parent) {
			if err := checkTrustedLinuxEntry(parent, fs, true); err != nil {
				return "", err
			}
			if parent == "/" {
				break
			}
		}
		return resolved, nil
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

func sudoRuleGrantsAll(line string) bool {
	if !strings.HasPrefix(line, "(ALL") {
		return false
	}
	closeIdx := strings.IndexByte(line, ')')
	if closeIdx < 0 {
		return false
	}
	rest := strings.TrimSpace(line[closeIdx+1:])
	if rest == "" {
		return false
	}
	for _, spec := range strings.Split(rest, ",") {
		cmd := strings.TrimSpace(spec)
		for {
			first, after, hasSpace := strings.Cut(cmd, " ")
			if strings.HasSuffix(first, ":") && len(first) > 1 {
				if !hasSpace {
					cmd = ""
					break
				}
				cmd = strings.TrimSpace(after)
				continue
			}
			break
		}
		if cmd == "ALL" {
			return true
		}
	}
	return false
}

// verifySudoEscalation verifies that sudo -l -U output grants (ALL) root escalation without targetpw blocking it.
func verifySudoEscalation(output string) error {
	var hasAllRule bool
	var targetpwBlocked bool

	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "(ALL") {
			if sudoRuleGrantsAll(trimmed) {
				hasAllRule = true
			}
			continue
		}
		if strings.HasPrefix(trimmed, "User ") {
			continue
		}
		tokens := strings.FieldsFunc(trimmed, func(r rune) bool {
			return r == ',' || unicode.IsSpace(r)
		})
		for _, tok := range tokens {
			switch tok {
			case "targetpw":
				targetpwBlocked = true
			case "!targetpw":
				targetpwBlocked = false
			}
		}
	}
	if targetpwBlocked {
		return errors.New("sudo targetpw is active and blocks root escalation")
	}
	if !hasAllRule {
		return errors.New("sudo -l output does not grant (ALL) root escalation")
	}
	return nil
}
