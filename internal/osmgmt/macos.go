// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

//go:build darwin

package osmgmt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golaps/internal/password"
	"golaps/internal/version"
)

const teamITChannelURL = ""

// Use open -a to activate Admin By Request because its URL scheme does not open the elevation prompt.
const (
	abrAppPath = "/Applications/Admin By Request.app"
	abrAppName = "Admin By Request"

	abrPollInterval = 2 * time.Second

	// Reserve time for the final vault write so GUI prompts cannot push the run past the MDM timeout.
	vaultWriteReserve = 5 * time.Minute

	dialogWait = 5 * time.Minute
)

type SwiftPayload struct {
	Action     string `json:"action"`
	TargetUser string `json:"targetUser"`
	TargetPass string `json:"targetPass"`
	OldPass    string `json:"oldPass,omitempty"`
	AdminUser  string `json:"adminUser,omitempty"`
	AdminPass  string `json:"adminPass,omitempty"`
	// Set AllowAdminReset true only for accounts without a Secure Token.
	AllowAdminReset bool `json:"allowAdminReset,omitempty"`
}

// changeOutcome mirrors ChangeOutcome in mac_helper.swift.
type changeOutcome int

const (
	changeOK           changeOutcome = 0
	changeODError      changeOutcome = 1
	changeAuthFailed   changeOutcome = 2
	changeLocked       changeOutcome = 3
	changeResetRefused changeOutcome = 4
	// OD 5402-5407: device password policy rejected the new password. Do not recreate the account.
	changePolicyRejected changeOutcome = 5
)

func (c changeOutcome) String() string {
	switch c {
	case changeOK:
		return "ok"
	case changeODError:
		return "od-error"
	case changeAuthFailed:
		return "auth-failed"
	case changeLocked:
		return "locked"
	case changeResetRefused:
		return "reset-refused"
	case changePolicyRejected:
		return "policy-rejected"
	}
	return fmt.Sprintf("unknown(%d)", int(c))
}

func (p SwiftPayload) secrets() []string {
	s := make([]string, 0, 3)
	for _, v := range []string{p.TargetPass, p.OldPass, p.AdminPass} {
		if v != "" {
			s = append(s, v)
		}
	}
	return s
}

// redactSecrets masks payload secrets in helper output before logging.
func redactSecrets(text string, secrets []string) string {
	for _, s := range secrets {
		text = strings.ReplaceAll(text, s, "[REDACTED]")
	}
	return text
}

type runner interface {
	Run(ctx context.Context, stdin, name string, args ...string) ([]byte, error)
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, stdin, name string, args ...string) ([]byte, error) {
	cmd := commandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	return cmd.CombinedOutput()
}

// exitCode returns ok=false if the process did not run or timed out.
func exitCode(err error) (int, bool) {
	var ec interface{ ExitCode() int }
	if errors.As(err, &ec) {
		return ec.ExitCode(), true
	}
	return -1, false
}

type promptResult struct {
	outcome           passwordOutcome
	user              string
	wrongPasswordRuns int
	windowFailedRuns int
	windowFailed     bool
}

type MacOSManager struct {
	run    runner
	sleep  func(time.Duration)                                                // injectable, so the phantom-recovery tests do not spend real seconds in opendirectoryd settle waits
	prompt func(ctx context.Context, targetUser, newPass string) promptResult // the token prompt. Injectable, because the real one shows a window at the console
	probe  func(ctx context.Context, url string) error                        // the vault reachability probe. Injectable, so preflight tests need no network
	now    func() time.Time                                                   // injectable clock for the heal cooldown
	healStatePath string
	escrowBridge BridgeEscrow
	openWindow func(ctx context.Context, uid, user string, req dialogRequest) (passwordWindow, error)
	promptStatePath string
	openApp func(ctx context.Context, uid, user, appName string) error
	authSocketPath string
	lstat func(string) (os.FileInfo, error)
	wrongPasswordPause time.Duration
	pauseTick time.Duration
}

func (m *MacOSManager) SetBridgeEscrow(escrow BridgeEscrow) { m.escrowBridge = escrow }

func NewManager() Manager {
	m := &MacOSManager{run: execRunner{}, sleep: time.Sleep, probe: probeVaultEndpoint, now: time.Now, healStatePath: healStatePath, lstat: os.Lstat}
	m.prompt = m.promptUserForToken
	m.authSocketPath = authSocketPath
	m.openApp = openAppAsUser
	m.openWindow = m.openAuthWindow
	m.promptStatePath = promptStatePath
	m.wrongPasswordPause = wrongPasswordPause
	m.pauseTick = pauseTick
	return m
}

// withReserve derives a sub-context capped at want while keeping reserve time for later steps.
func withReserve(ctx context.Context, want, reserve time.Duration) (context.Context, context.CancelFunc) {
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if available := remaining - reserve; available < want {
			if available > 0 {
				want = available
			} else if remaining > 0 {
				want = min(want, remaining)
			} else {
				want = 0
			}
		}
	}
	return context.WithTimeout(ctx, want)
}

// runSwiftHelper returns the helper exit code as a verdict. A non-nil error means the helper failed to run.
func (m *MacOSManager) runSwiftHelper(ctx context.Context, payload SwiftPayload) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	data, err := json.Marshal(payload)
	if err != nil {
		return -1, fmt.Errorf("failed to marshal JSON payload: %w", err)
	}

	if err := m.trustedBinary(helperPath); err != nil {
		log.Printf("[ERROR] The helper failed its integrity check, no password was sent to it: %v\n", err)
		return -1, fmt.Errorf("refusing to run the helper: %w", err)
	}
	out, err := m.run.Run(ctx, string(data), helperPath)
	// Log [SWIFT] lines on success too so admin-reset fallbacks and sysadminctl refusals stay visible.
	output := redactSecrets(strings.TrimSpace(string(out)), payload.secrets())
	for _, line := range strings.Split(output, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			log.Printf("%s", line)
		}
	}
	if err == nil {
		return 0, nil
	}
	if code, ok := exitCode(err); ok && code >= 0 {
		return code, nil
	}
	return -1, fmt.Errorf("swift helper error: %w | output: %s", err, output)
}

func (m *MacOSManager) callSwiftHelper(ctx context.Context, payload SwiftPayload) error {
	code, err := m.runSwiftHelper(ctx, payload)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("swift helper exited %d", code)
	}
	return nil
}

var macSerialPattern = regexp.MustCompile(`^[A-Z0-9]{8,20}$`)

// parseMacSerial checks the hardware serial so missing values never collide on one vault record.
func parseMacSerial(ioregOutput string) (string, error) {
	re := regexp.MustCompile(`"IOPlatformSerialNumber" = "([^"]+)"`)
	matches := re.FindStringSubmatch(ioregOutput)
	if len(matches) < 2 {
		return "", errors.New("ioreg reported no IOPlatformSerialNumber")
	}
	serial := strings.TrimSpace(matches[1])
	if serial == "" || strings.EqualFold(serial, "Unknown") || !macSerialPattern.MatchString(serial) {
		return "", fmt.Errorf("ioreg reported an unusable serial %q", serial)
	}
	return serial, nil
}

func (m *MacOSManager) GetSystemInfo(ctx context.Context) (string, string, error) {
	log.Printf("[INFO] --- GoLAPS macOS Agent (Version: %s) --- \n", version.Version)

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "UnknownHost"
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cmd := commandContext(ctx, toolIoreg, "-c", "IOPlatformExpertDevice", "-d", "2")
	output, err := cmd.Output()
	if err != nil {
		return hostname, "", fmt.Errorf("could not read the serial through ioreg: %w", err)
	}
	serial, err := parseMacSerial(string(output))
	if err != nil {
		return hostname, "", err
	}
	return hostname, serial, nil
}

// userAccountExists separates check errors from a missing account to avoid accidental recreation.
func (m *MacOSManager) userAccountExists(ctx context.Context, user string) (bool, error) {
	out, err := m.run.Run(ctx, "", toolID, "-u", user)
	if err == nil {
		return true, nil
	}
	if ctx.Err() != nil {
		return false, fmt.Errorf("could not check whether %s exists: %w", user, ctx.Err())
	}
	if code, ok := exitCode(err); ok {
		if !strings.Contains(string(out), "no such user") {
			log.Printf("[INFO] id -u %s exited %d: %s\n", user, code, strings.TrimSpace(string(out)))
		}
		return false, nil
	}
	return false, fmt.Errorf("could not run id -u %s: %w", user, err)
}

// EnsureUserAndChangePassword rotates the target admin using candidates in order, or recreates it if unusable.
func (m *MacOSManager) EnsureUserAndChangePassword(ctx context.Context, user string, candidates []string, newPassword string) error {
	if len(candidates) == 0 {
		candidates = []string{""}
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	userExists, err := m.userAccountExists(ctx, user)
	if err != nil {
		return err
	}

	if !userExists {
		log.Printf("[WARNING] macOS user %s not found. Initiating Auto-Healing...\n", user)
		return m.createHiddenAdmin(ctx, user, "IT Admin", newPassword)
	}

	// Require a definite token-state answer before taking any destructive heal path.
	hasToken, tokenErr := m.secureTokenState(ctx, user)
	if tokenErr != nil {
		return fmt.Errorf("refusing to auto-heal %s: could not determine its Secure Token state: %w", user, tokenErr)
	}

	// Accounts without a Secure Token rotate in place via administrative reset instead of daily recreation.
	if !hasToken {
		return m.rotateTokenless(ctx, user, candidates, newPassword)
	}

	// Recreate if OpenDirectory still blocks authentication after preflight soft repairs.
	out, pwErr := m.run.Run(ctx, "", toolPwpolicy, "-u", user, "authentication-allowed")
	verdict := strings.TrimSpace(string(out))
	if pwErr != nil && verdict == "" {
		log.Printf("[WARNING] pwpolicy gave no authentication-allowed verdict for %s (%v) — skipping the gate this run; the rotation below still verifies the real state.\n", user, pwErr)
	} else if strings.Contains(verdict, "not") && strings.Contains(verdict, "allowed to authenticate") {
		log.Printf("[WARNING] %s holds a Secure Token but cannot authenticate (%s). Escalating to account recreation — the token grant afterwards may prompt the console user via Admin By Request.\n", user, verdict)
		return m.healAccount(ctx, user, newPassword)
	}

	// Keep AllowAdminReset false for Secure Token holders to avoid phantom resets or broken FileVault keys.
	log.Printf("[INFO] User %s found with intact Secure Token. Delegating password reset to Swift Helper...", user)

	// On a lock verdict, clear failedLoginCount once and retry to distinguish transient lockouts from persistent OD 5305.
	var outcome int
	clearUsed := false
	for i, candidate := range candidates {
		if i == 1 {
			log.Printf("[INFO] The primary password candidate for %s no longer authenticates; trying the alternate one before escalating to recreation.\n", user)
		} else if i > 1 {
			log.Printf("[INFO] Password candidate %d of %d for %s did not authenticate either; trying the next one before escalating to recreation.\n", i, len(candidates), user)
		}
		var err error
		outcome, err = m.runSwiftHelper(ctx, SwiftPayload{
			Action:          "change_password",
			TargetUser:      user,
			TargetPass:      newPassword,
			OldPass:         candidate,
			AllowAdminReset: false,
		})
		if err != nil {
			return fmt.Errorf("failed to change password natively: %w", err)
		}
		if changeOutcome(outcome) == changeLocked && !clearUsed {
			clearUsed = true
			log.Printf("[WARNING] %s reports locked (OD 5305) although its failed-login counter was cleared at preflight — clearing it again and retrying the authenticated change once before anything destructive.\n", user)
			m.clearFailedLoginCounter(ctx, user)
			outcome, err = m.runSwiftHelper(ctx, SwiftPayload{
				Action:          "change_password",
				TargetUser:      user,
				TargetPass:      newPassword,
				OldPass:         candidate,
				AllowAdminReset: false,
			})
			if err != nil {
				return fmt.Errorf("failed to change password natively: %w", err)
			}
		}
		if changeOutcome(outcome) == changeAuthFailed && i < len(candidates)-1 {
			continue
		}
		if changeOutcome(outcome) == changeOK && i > 0 {
			log.Printf("[SUCCESS] The alternate password candidate was the live one — rotation completed without recreation.\n")
			log.Printf("[INFO] Password candidate %d of %d for %s was the live one.\n", i+1, len(candidates), user)
		}
		break
	}

	switch changeOutcome(outcome) {
	case changeOK:
		return nil
	case changeAuthFailed, changeLocked:
		log.Printf("[WARNING] %s holds a Secure Token but the recorded password no longer authenticates (%s). Escalating to account recreation rather than an administrative reset.\n", user, changeOutcome(outcome))
		return m.healAccount(ctx, user, newPassword)
	case changePolicyRejected:
		return fmt.Errorf("the device's password policy rejected the generated password for %s (OD 5402-5407): %w — not recreating a healthy account; the next run retries with a new password", user, ErrPolicyRejected)
	default:
		return fmt.Errorf("rotating the password for %s failed (%s)", user, changeOutcome(outcome))
	}
}

// rotateTokenless tries authenticated changes first and enables AllowAdminReset only on the final candidate.
func (m *MacOSManager) rotateTokenless(ctx context.Context, user string, candidates []string, newPassword string) error {
	log.Printf("[INFO] %s holds no Secure Token. Rotating it in place (authenticated change, administrative reset as fallback) instead of recreating it — the token grant that follows is what restores the SEP chain, and keeping the account spares the device a daily recreation.\n", user)
	if len(candidates) == 0 {
		candidates = []string{""}
	}

	var outcome int
	for i := 0; i < len(candidates); i++ {
		last := i == len(candidates)-1
		if i > 0 {
			log.Printf("[INFO] Password candidate %d of %d for %s did not authenticate; trying the next one before the administrative reset.\n", i, len(candidates), user)
		}
		var err error
		outcome, err = m.runSwiftHelper(ctx, SwiftPayload{
			Action:          "change_password",
			TargetUser:      user,
			TargetPass:      newPassword,
			OldPass:         candidates[i],
			AllowAdminReset: last,
		})
		if err != nil {
			return fmt.Errorf("failed to change password natively: %w", err)
		}
		if last {
			break
		}
		if changeOutcome(outcome) == changeAuthFailed {
			continue
		}
		if changeOutcome(outcome) == changeLocked {
			log.Printf("[WARNING] %s reports locked (OD 5305) during the in-place rotation; skipping the remaining password candidates and going to the administrative reset.\n", user)
			i = len(candidates) - 2
			continue
		}
		break
	}

	switch changeOutcome(outcome) {
	case changeOK:
		log.Printf("[SUCCESS] %s rotated in place without recreation.\n", user)
		return nil
	case changePolicyRejected:
		return fmt.Errorf("the device's password policy rejected the generated password for %s (OD 5402-5407): %w — not recreating a healthy account; the next run retries with a new password", user, ErrPolicyRejected)
	case changeResetRefused, changeODError, changeAuthFailed, changeLocked:
		log.Printf("[WARNING] %s could not be rotated in place (%s). Escalating to account recreation.\n", user, changeOutcome(outcome))
		return m.healAccount(ctx, user, newPassword)
	default:
		return fmt.Errorf("rotating the password for %s failed (%s)", user, changeOutcome(outcome))
	}
}

// healAccount deletes and recreates targetUser, using laps-bridge if macOS refuses to delete the last admin.
func (m *MacOSManager) healAccount(ctx context.Context, user, newPassword string) error {
	if err := m.healCooldownError(user); err != nil {
		return err
	}
	if err := m.soleAccountError(ctx, user); err != nil {
		return err
	}
	if err := m.recreateAccount(ctx, user, newPassword); err != nil {
		return err
	}
	m.recordHeal(user)
	return nil
}

// soleAccountError aborts recreation if user is both the only admin and the only Secure Token holder.
func (m *MacOSManager) soleAccountError(ctx context.Context, user string) error {
	hasToken, err := m.secureTokenState(ctx, user)
	if err != nil || !hasToken {
		return nil
	}
	if m.otherTokenHolderExists(ctx, user) {
		return nil
	}
	if m.otherAdminExists(ctx, user) {
		return nil
	}
	msg := fmt.Sprintf("[SOLE ACCOUNT] %s is the only admin and the only Secure Token holder; macOS refuses to delete it. Recreation is impossible. Check the vault record: a reassigned or re-enrolled Mac still carries the previous owner's password; the legacy enrollment password is tried last.", user)
	log.Println(msg)
	return errors.New(msg)
}

func (m *MacOSManager) otherTokenHolderExists(ctx context.Context, user string) bool {
	if out, err := m.run.Run(ctx, "", toolDiskutil, "apfs", "listCryptoUsers", "/"); err == nil {
		if holders := countLocalCryptoUsers(string(out)); holders >= 0 {
			return holders > 1
		}
	}
	log.Printf("[WARNING] diskutil did not list the crypto users of the system volume. Falling back to the per-account Secure Token scan.\n")
	for _, holder := range m.getTokenHolders(ctx) {
		if holder != user {
			return true
		}
	}
	return false
}

func (m *MacOSManager) otherAdminExists(ctx context.Context, user string) bool {
	out, err := m.run.Run(ctx, "", toolDscl, ".", "-list", "/Users", "UniqueID")
	if err != nil {
		log.Printf("[WARNING] Could not enumerate local users for the sole-account check: %v\n", err)
		return true
	}
	for _, name := range parseLocalUsers(string(out)) {
		if name != user && m.inAdminGroup(ctx, name) {
			return true
		}
	}
	return false
}

func (m *MacOSManager) recreateAccount(ctx context.Context, user, newPassword string) error {
	log.Printf("[WARNING] User %s exists but is unusable (no token, or locked beyond repair). Deleting account to heal crypto-chain...\n", user)

	if out, err := m.run.Run(ctx, "", toolSysadminctl, "-deleteUser", user); err != nil {
		log.Printf("[WARNING] sysadminctl -deleteUser %s failed: %v | output: %s\n", user, err, strings.TrimSpace(string(out)))
	}
	// Never fall back to dscl -delete because it bypasses the last-admin guard and orphans the SEP identity.
	stillThere, err := m.userAccountExists(ctx, user)
	if err != nil {
		return err
	}
	if !stillThere {
		return m.createHiddenAdmin(ctx, user, "IT Admin", newPassword)
	}

	// Target is the last admin. Create a temporary bridge admin so sysadminctl allows deletion.
	log.Printf("[WARNING] %s survived deletion — it is likely the last admin (Admin By Request demotes the humans). Creating a temporary bridge admin...\n", user)
	return m.withBridgeAdmin(ctx, user, func() error {
		if out, err := m.run.Run(ctx, "", toolSysadminctl, "-deleteUser", user); err != nil {
			log.Printf("[WARNING] sysadminctl -deleteUser %s (with bridge) failed: %v | output: %s\n", user, err, strings.TrimSpace(string(out)))
		}
		stillExists, err := m.userAccountExists(ctx, user)
		if err != nil {
			return err
		}
		if stillExists {
			return fmt.Errorf("could not delete %s even with a bridge admin present: the account still exists", user)
		}
		log.Printf("[INFO] %s deleted with the bridge admin holding the admin count. Recreating it inside the bridge window...\n", user)
		// Recreate inside the bridge window so a failure never leaves the Mac without an admin.
		return m.createHiddenAdmin(ctx, user, "IT Admin", newPassword)
	})
}

func (m *MacOSManager) createHiddenAdmin(ctx context.Context, name, fullName, pass string) error {
	addUser := func() error {
		out, err := m.run.Run(ctx, pass+"\n", toolSysadminctl, "-addUser", name, "-fullName", fullName, "-password", "-", "-admin")
		output := redactSecrets(strings.TrimSpace(string(out)), []string{pass})
		if output != "" {
			log.Printf("[INFO] sysadminctl -addUser %s output: %s\n", name, output)
		}
		if err != nil {
			return fmt.Errorf("failed to create %s: %w | output: %s", name, err, output)
		}
		if out, err := m.run.Run(ctx, "", toolDscl, ".", "create", "/Users/"+name, "IsHidden", "1"); err != nil {
			log.Printf("[WARNING] Could not hide %s from the login window: %v | output: %s\n", name, err, strings.TrimSpace(string(out)))
		}
		m.sleep(2 * time.Second)
		return nil
	}

	if err := addUser(); err != nil {
		return err
	}
	created, err := m.userAccountExists(ctx, name)
	if err != nil {
		return err
	}
	if created {
		return nil
	}

	log.Printf("[WARNING] sysadminctl reported no error but %s does not exist after creation. Resetting the OD cache and retrying once...\n", name)
	if out, err := m.run.Run(ctx, "", toolOdutil, "reset", "cache"); err != nil {
		log.Printf("[WARNING] odutil reset cache failed: %v | output: %s\n", err, strings.TrimSpace(string(out)))
	}
	m.sleep(3 * time.Second)
	if created, err = m.userAccountExists(ctx, name); err != nil {
		return err
	}
	if !created {
		if err := addUser(); err != nil {
			return err
		}
		if created, err = m.userAccountExists(ctx, name); err != nil {
			return err
		}
	}
	if !created {
		// Last resort: assemble the account via dscl and set its password over stdin.
		log.Printf("[WARNING] sysadminctl create-phantom persists for %s. Building the account directly via dscl as root...\n", name)
		if err := m.createAdminViaDscl(ctx, name, fullName, pass); err != nil {
			return fmt.Errorf("sysadminctl silently failed twice and the direct dscl build failed too: %w", err)
		}
		if created, err = m.userAccountExists(ctx, name); err != nil {
			return err
		}
		if !created {
			return fmt.Errorf("%s still does not exist after sysadminctl retries and a direct dscl build", name)
		}
	}
	log.Printf("[SUCCESS] %s exists after the create-phantom recovery.\n", name)
	return nil
}

// createAdminViaDscl builds a local admin without passing any password in argv, then sets the password via mac_helper.
func (m *MacOSManager) createAdminViaDscl(ctx context.Context, name, fullName, pass string) error {
	out, err := m.run.Run(ctx, "", toolDscl, ".", "-list", "/Users", "UniqueID")
	if err != nil {
		return fmt.Errorf("could not list existing UIDs: %w | %s", err, strings.TrimSpace(string(out)))
	}
	taken := map[int]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 {
			if id, err := strconv.Atoi(f[1]); err == nil {
				taken[id] = true
			}
		}
	}
	uid := 501
	for taken[uid] {
		uid++
	}

	steps := [][]string{
		{"-create", "/Users/" + name},
		{"-create", "/Users/" + name, "UserShell", "/bin/zsh"},
		{"-create", "/Users/" + name, "RealName", fullName},
		{"-create", "/Users/" + name, "UniqueID", strconv.Itoa(uid)},
		{"-create", "/Users/" + name, "PrimaryGroupID", "20"},
		{"-create", "/Users/" + name, "NFSHomeDirectory", "/Users/" + name},
		{"-create", "/Users/" + name, "IsHidden", "1"},
	}
	for _, args := range steps {
		if out, err := m.run.Run(ctx, "", toolDscl, append([]string{"."}, args...)...); err != nil {
			return fmt.Errorf("dscl %s failed: %w | %s", args[0]+" "+args[1], err, strings.TrimSpace(string(out)))
		}
	}

	// Set the password over stdin via mac_helper before adding the account to the admin group.
	if err := m.callSwiftHelper(ctx, SwiftPayload{
		Action:          "change_password",
		TargetUser:      name,
		TargetPass:      pass,
		AllowAdminReset: true,
	}); err != nil {
		return fmt.Errorf("account %s built via dscl, but setting its password over stdin failed (the record has no credential and is not an admin; the next run's auto-heal recycles it): %w", name, err)
	}
	if out, err := m.run.Run(ctx, "", toolDseditgroup, "-o", "edit", "-a", name, "-t", "user", "admin"); err != nil {
		return fmt.Errorf("could not add %s to the admin group: %w | %s", name, err, strings.TrimSpace(string(out)))
	}
	log.Printf("[INFO] %s built via dscl (UID %d): password set over stdin, then added to the admin group.\n", name, uid)
	m.sleep(2 * time.Second)
	return nil
}

// bridgeFullName distinguishes a GoLAPS-created bridge from a legacy laps-bridge account.
const bridgeFullName = "IT Recovery Bridge"

// withBridgeAdmin runs fn with laps-bridge present after escrowing its password and checking that another token holder exists.
func (m *MacOSManager) withBridgeAdmin(ctx context.Context, targetUser string, fn func() error) error {
	bridge := LegacyBridgeAdmin

	if exists, err := m.userAccountExists(ctx, bridge); err != nil {
		return err
	} else if !exists {
		if err := m.bridgeSafeToCreate(ctx); err != nil {
			return err
		}
		if m.escrowBridge == nil {
			return fmt.Errorf("no escrow route for the bridge password; not creating %s", bridge)
		}
		bridgePass, err := password.Generate(0)
		if err != nil {
			return fmt.Errorf("could not generate a password for the bridge admin: %w", err)
		}
		escrowCtx, cancelEscrow := withReserve(ctx, 60*time.Second, vaultWriteReserve)
		err = m.escrowBridge(escrowCtx, bridgePass)
		cancelEscrow()
		if err != nil {
			return fmt.Errorf("could not escrow the bridge password before creating %s, not creating it: %w", bridge, err)
		}
		log.Printf("[INFO] Bridge password escrowed to the vault record before the account is created.\n")
		if err := m.createHiddenAdmin(ctx, bridge, bridgeFullName, bridgePass); err != nil {
			return fmt.Errorf("could not create the bridge admin %s: %w", bridge, err)
		}
	} else {
		log.Printf("[INFO] Reusing the existing %s account as the bridge admin.\n", bridge)
		// Restore admin membership only when the account is a hidden LAPS bridge or hidden legacy admin.
		if !m.inAdminGroup(ctx, bridge) {
			hidden := m.isHiddenAccount(ctx, bridge)
			realName := m.realName(ctx, bridge)
			if !hidden || !(m.isBridgeAccount(ctx) || realName == bridge) {
				return fmt.Errorf("%s exists but is not a LAPS bridge or the legacy admin (hidden=%v, RealName %q); not promoting it to admin", bridge, hidden, realName)
			}
			log.Printf("[WARNING] The existing bridge admin %s is not in the admin group. The run adds it back before the heal.\n", bridge)
			if out, err := m.run.Run(ctx, "", toolDseditgroup, "-o", "edit", "-a", bridge, "-t", "user", "admin"); err != nil {
				return fmt.Errorf("could not add the existing bridge admin %s back to the admin group: %w | output: %s", bridge, err, strings.TrimSpace(string(out)))
			}
			log.Printf("[BRIDGE PROMOTED] %s was added back to the admin group for this heal.\n", bridge)
		}
	}

	fnErr := fn()

	// Never delete the bridge if the target is missing or if the bridge holds a Secure Token.
	if targetThere, err := m.userAccountExists(ctx, targetUser); err != nil || !targetThere {
		log.Printf("[ERROR] Keeping bridge admin %s: the target %s is missing and the bridge is the only admin left (check err: %v). The next run will reuse and then remove it.\n", bridge, targetUser, err)
		return fnErr
	}
	if hasToken, err := m.secureTokenState(ctx, bridge); err != nil || hasToken {
		log.Printf("[INFO] Keeping %s for now (Secure Token state: enabled=%v, err=%v). CleanupLegacyAdmin removes it once %s holds a token.\n", bridge, hasToken, err, targetUser)
		return fnErr
	}
	if out, err := m.run.Run(ctx, "", toolSysadminctl, "-deleteUser", bridge); err != nil {
		log.Printf("[WARNING] sysadminctl -deleteUser %s failed: %v | output: %s\n", bridge, err, strings.TrimSpace(string(out)))
	}
	if still, err := m.userAccountExists(ctx, bridge); err == nil && still {
		log.Printf("[WARNING] Bridge admin %s could not be removed this run — CleanupLegacyAdmin retires it on a later run once %s holds a Secure Token.\n", bridge, targetUser)
	}
	return fnErr
}

func (m *MacOSManager) ManageSecureToken(ctx context.Context, targetUser, newPass string, availableCreds map[string]string) string {
	status := m.manageSecureToken(ctx, targetUser, newPass, availableCreds)
	verdict := "ok"
	if status == TokenStatusDisabledDeadlock {
		verdict = "deadlock"
	}
	log.Println(m.bridgeReport(ctx, availableCreds, verdict))
	return status
}

func (m *MacOSManager) manageSecureToken(ctx context.Context, targetUser, newPass string, availableCreds map[string]string) string {
	if hasToken, err := m.secureTokenState(ctx, targetUser); err != nil {
		log.Printf("[WARNING] Could not read the Secure Token state of %s (%v). Continuing as if it had none; the grant path verifies the result.\n", targetUser, err)
	} else if hasToken {
		log.Printf("[SUCCESS] Verified: %s already has an active Secure Token.\n", targetUser)
		m.clearPromptState()
		return "ENABLED (Auto-Migrated or Existing)"
	}

	log.Printf("[INFO] Verified: %s lacks a Secure Token. Scanning macOS for token holders...\n", targetUser)

	tokenHolders := m.getTokenHolders(ctx)

	for _, admin := range tokenHolders {
		log.Printf("[INFO] Evaluating token holder candidate: %s\n", admin)

		adminPass, source, ok := m.candidatePassword(ctx, admin, targetUser, availableCreds)
		if !ok {
			continue
		}
		if !m.candidateUsable(ctx, admin) {
			continue
		}

		log.Printf("[INFO] -> Trying the %s password for %s (one attempt)...\n", source, admin)
		grantErr := m.grantSecureTokenSilently(ctx, targetUser, newPass, admin, adminPass)
		if grantErr == nil {
			log.Printf("[SUCCESS] Secure Token granted silently via %s (%s).\n", admin, source)
			if source == "MDM Legacy" {
				return "ENABLED (Silent - MDM)"
			}
			return "ENABLED (Silent - Vault)"
		}
		log.Printf("[WARNING] %s password failed for %s. Details: %v\n", source, admin, grantErr)
	}

	log.Println("[WARNING] All silent grant attempts failed or no matching passwords found. Triggering GUI Prompt...")
	prompt := m.prompt(ctx, targetUser, newPass)
	if prompt.outcome == passwordOK {
		return "ENABLED (Via GUI Prompt)"
	}

	if len(tokenHolders) == 1 && tokenHolders[0] == LegacyBridgeAdmin {
		log.Printf("[DEADLOCK] %s is the only Secure Token holder on this Mac and no stored password authenticates as it. %s cannot receive a token and %s cannot be retired. Recovery: log in once as %s at the login window (\"Other...\") with its vault password; the escrowed bootstrap token grants it a Secure Token during that login, and the next run removes %s. Erase the Mac only if that fails.\n", LegacyBridgeAdmin, targetUser, LegacyBridgeAdmin, targetUser, LegacyBridgeAdmin)
		return TokenStatusDisabledDeadlock
	}

	// Report consecutive wrong-password or killed-window streaks as hard failures even when MDM recovery exists.
	if prompt.outcome == passwordFailed && prompt.wrongPasswordRuns >= wrongPasswordRedAfter {
		log.Printf("[WRONG PASSWORD STREAK] %s entered a wrong password in each of %d attempts in %d consecutive runs; IT follow-up is needed.\n", prompt.user, maxPasswordAttempts, prompt.wrongPasswordRuns)
		return TokenStatusDisabledWrongPassword
	}
	if prompt.windowFailed && prompt.windowFailedRuns >= windowFailedRedAfter {
		log.Printf("[WINDOW ENDED STREAK] %s ended the password window before an answer in %d consecutive runs; IT follow-up is needed.\n", prompt.user, prompt.windowFailedRuns)
		return TokenStatusDisabledWindowKilled
	}

	if m.recoveryCoveredByMDM(ctx) {
		log.Printf("[WARNING] %s still holds no Secure Token after the prompt, but the device has a personal recovery key and an escrowed bootstrap token — reporting a covered degradation instead of a failure; the grant retries on the next run.\n", targetUser)
		return TokenStatusDisabledCovered
	}

	return "DISABLED (Review Required)"
}

// recoveryCoveredByMDM returns true only when both a local PRK and an escrowed bootstrap token exist (fails closed).
func (m *MacOSManager) recoveryCoveredByMDM(ctx context.Context) bool {
	ctx, cancel := withReserve(ctx, 20*time.Second, vaultWriteReserve)
	defer cancel()
	out, err := m.run.Run(ctx, "", toolFdesetup, "haspersonalrecoverykey")
	if err != nil || !strings.EqualFold(strings.TrimSpace(string(out)), "true") {
		log.Printf("[INFO] No usable personal recovery key (fdesetup: %q, err: %v) — MDM cannot recover FileVault without the service admin.\n", strings.TrimSpace(string(out)), err)
		return false
	}
	out, err = m.run.Run(ctx, "", toolProfiles, "status", "-type", "bootstraptoken")
	if err != nil || !bootstrapTokenEscrowed(string(out)) {
		log.Printf("[INFO] Bootstrap token is not escrowed (profiles: %q, err: %v).\n", strings.TrimSpace(string(out)), err)
		return false
	}
	return true
}

func bootstrapTokenEscrowed(output string) bool {
	return strings.Contains(strings.ToLower(output), "escrowed to server: yes")
}

// candidatePassword selects one stored password for admin. GoLAPS bridges never use the legacy MDM password.
func (m *MacOSManager) candidatePassword(ctx context.Context, admin, targetUser string, availableCreds map[string]string) (pass, source string, ok bool) {
	if pass, found := availableCreds[admin]; found && pass != "" {
		return pass, "1Password specific", true
	}
	if admin == LegacyBridgeAdmin && m.isBridgeAccount(ctx) {
		log.Printf("[INFO] -> %s is a LAPS bridge with no escrowed password; no silent grant is possible through it.\n", admin)
		return "", "", false
	}
	if !isServiceAccount(admin, targetUser, availableCreds) {
		log.Printf("[INFO] -> Skipping MDM Legacy Password for %s: not an IT-managed service account.\n", admin)
		return "", "", false
	}
	if pass, found := availableCreds["MDM_FALLBACK_PASS"]; found && pass != "" {
		return pass, "MDM Legacy", true
	}
	log.Printf("[INFO] -> No stored password for %s; skipping the silent grant through it.\n", admin)
	return "", "", false
}

// candidateUsable skips candidates blocked by pwpolicy or at conflictThreshold to avoid locking them out.
func (m *MacOSManager) candidateUsable(ctx context.Context, admin string) bool {
	if verdict := m.pwpolicyVerdict(ctx, admin); authenticationBlocked(verdict) {
		log.Printf("[INFO] -> Skipping the silent grant through %s: %s\n", admin, verdict)
		return false
	}
	if count := m.failedLoginCount(ctx, admin); count >= conflictThreshold {
		log.Printf("[INFO] -> Skipping the silent grant through %s: %d failed authentications are already recorded (threshold %d).\n", admin, count, conflictThreshold)
		return false
	}
	return true
}

func isServiceAccount(login, targetUser string, availableCreds map[string]string) bool {
	if login == targetUser || login == LegacyBridgeAdmin {
		return true
	}
	_, known := availableCreds[login]
	return known
}

func parseSecureTokenStatus(output string) (enabled, ok bool) {
	// Match full phrases so ENABLED never matches DISABLED.
	switch {
	case strings.Contains(output, "is ENABLED"), strings.Contains(output, "is ON"):
		return true, true
	case strings.Contains(output, "is DISABLED"), strings.Contains(output, "is OFF"):
		return false, true
	}
	return false, false
}

// secureTokenState returns an error when macOS gives no definite ENABLED/DISABLED answer.
func (m *MacOSManager) secureTokenState(ctx context.Context, user string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	out, err := m.run.Run(ctx, "", toolSysadminctl, "-secureTokenStatus", user)
	text := strings.TrimSpace(string(out))

	if enabled, ok := parseSecureTokenStatus(text); ok {
		return enabled, nil
	}
	if err != nil {
		return false, fmt.Errorf("sysadminctl -secureTokenStatus %s failed: %w | output: %s", user, err, text)
	}
	return false, fmt.Errorf("could not read the Secure Token state of %s from sysadminctl output: %q", user, text)
}

func (m *MacOSManager) grantSecureTokenSilently(ctx context.Context, targetUser, targetPass, adminUser, adminPass string) error {
	if err := m.callSwiftHelper(ctx, SwiftPayload{
		Action:     "grant_token",
		TargetUser: targetUser,
		TargetPass: targetPass,
		AdminUser:  adminUser,
		AdminPass:  adminPass,
	}); err != nil {
		return fmt.Errorf("swift process failed: %w", err)
	}

	m.sleep(3 * time.Second)

	enabled, err := m.secureTokenState(ctx, targetUser)
	if err != nil {
		return fmt.Errorf("swift process returned success (exit 0) but the resulting token state is unknown: %w", err)
	}
	if !enabled {
		return errors.New("swift process returned success (exit 0), but token is still DISABLED")
	}
	return nil
}

// verifyPasswordCode checks credentials through mac_helper over stdin instead of dscl -authonly (argv).
func (m *MacOSManager) verifyPasswordCode(ctx context.Context, user, pass string) (int, error) {
	return m.runSwiftHelper(ctx, SwiftPayload{
		Action:     "verify_password",
		TargetUser: user,
		TargetPass: pass,
	})
}

func (m *MacOSManager) VerifyPassword(ctx context.Context, user, pass string) (bool, error) {
	code, err := m.verifyPasswordCode(ctx, user, pass)
	if err != nil {
		return false, err
	}
	switch changeOutcome(code) {
	case changeOK:
		return true, nil
	case changeAuthFailed:
		return false, nil
	}
	return false, fmt.Errorf("the helper could not tell whether the password is live (%s)", changeOutcome(code))
}

func (m *MacOSManager) verifyUserPassword(ctx context.Context, user, pass string) bool {
	code, err := m.verifyPasswordCode(ctx, user, pass)
	if err == nil && code != 0 {
		err = fmt.Errorf("swift helper exited %d", code)
	}
	if err != nil {
		log.Printf("[INFO] Password verification for %s did not pass: %v\n", user, err)
		return false
	}
	return true
}

// bridgeSafeToCreate checks that another local user already holds a Secure Token (ignoring PRK and bootstrap token).
func (m *MacOSManager) bridgeSafeToCreate(ctx context.Context) error {
	holders := -1
	if out, err := m.run.Run(ctx, "", toolDiskutil, "apfs", "listCryptoUsers", "/"); err == nil {
		holders = countLocalCryptoUsers(string(out))
	}
	if holders > 0 {
		return nil
	}
	if holders < 0 {
		log.Printf("[WARNING] diskutil did not list the crypto users of the system volume. Falling back to the per-account Secure Token scan.\n")
		if len(m.getTokenHolders(ctx)) > 0 {
			return nil
		}
	}
	log.Printf("[NO TOKEN HOLDER] heal stopped: no local account holds a Secure Token. A new bridge admin would receive the first Secure Token and the volume ownership. The target account stays as it is.\n")
	log.Printf("BRIDGE: bridge=absent token=no password=unknown verdict=no-token-holder\n")
	return fmt.Errorf("%w no local account holds a Secure Token; refusing to create the bridge admin %s. Recovery: log in once as the target at the login window (\"Other...\") with its vault password, the escrowed bootstrap token then grants it a Secure Token, and the next run continues", ErrNoTokenHolder, LegacyBridgeAdmin)
}

func countLocalCryptoUsers(output string) int {
	if !strings.Contains(output, "Cryptographic user") {
		return -1
	}
	return strings.Count(output, "Local Open Directory User")
}

func (m *MacOSManager) isBridgeAccount(ctx context.Context) bool {
	out, err := m.run.Run(ctx, "", toolDscl, ".", "-read", "/Users/"+LegacyBridgeAdmin, "RealName")
	return err == nil && strings.Contains(string(out), bridgeFullName)
}

func (m *MacOSManager) dsclValue(ctx context.Context, user, attr string) (string, error) {
	out, err := m.run.Run(ctx, "", toolDscl, ".", "-read", "/Users/"+user, attr)
	if err != nil {
		return "", fmt.Errorf("could not read %s of %s: %w | %s", attr, user, err, strings.TrimSpace(string(out)))
	}
	_, value, found := strings.Cut(string(out), attr+":")
	if !found {
		return "", fmt.Errorf("%s has no %s attribute", user, attr)
	}
	return strings.TrimSpace(value), nil
}

func (m *MacOSManager) realName(ctx context.Context, user string) string {
	name, _ := m.dsclValue(ctx, user, "RealName")
	return name
}

func (m *MacOSManager) isHiddenAccount(ctx context.Context, user string) bool {
	value, err := m.dsclValue(ctx, user, "IsHidden")
	return err == nil && value == "1"
}

func (m *MacOSManager) bridgeReport(ctx context.Context, availableCreds map[string]string, verdict string) string {
	kind, token, pw := "absent", "no", "unknown"
	if exists, err := m.userAccountExists(ctx, LegacyBridgeAdmin); err == nil && exists {
		kind = "legacy"
		if m.isBridgeAccount(ctx) {
			kind = "bridge"
		}
		if enabled, err := m.secureTokenState(ctx, LegacyBridgeAdmin); err == nil && enabled {
			token = "yes"
		}
		if _, ok := availableCreds[LegacyBridgeAdmin]; ok {
			pw = "vault"
		}
	}
	return fmt.Sprintf("BRIDGE: bridge=%s token=%s password=%s verdict=%s", kind, token, pw, verdict)
}

// getTokenHolders scans local accounts with sysadminctl instead of fdesetup list, which omits non-FileVault token holders.
func (m *MacOSManager) getTokenHolders(ctx context.Context) []string {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	var holders []string

	out, err := m.run.Run(ctx, "", toolDscl, ".", "-list", "/Users", "UniqueID")
	if err != nil {
		log.Printf("[WARNING] Could not enumerate local users: %v\n", err)
	} else {
		for _, name := range parseLocalUsers(string(out)) {
			enabled, err := m.secureTokenState(ctx, name)
			if err != nil {
				log.Printf("[WARNING] Skipping %s as a token-holder candidate: %v\n", name, err)
				continue
			}
			if enabled {
				holders = append(holders, name)
			}
		}
	}

	if len(holders) == 0 {
		log.Println("[WARNING] No Secure Token holder found among local accounts.")
	}

	return holders
}

// parseLocalUsers returns non-system accounts (UID >= 500) from dscl output.
func parseLocalUsers(dsclOutput string) []string {
	var users []string
	for _, line := range strings.Split(dsclOutput, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		if uid, err := strconv.Atoi(fields[1]); err != nil || uid < 500 {
			continue
		}
		users = append(users, fields[0])
	}
	return users
}

func (m *MacOSManager) promptUserForToken(ctx context.Context, targetUser, targetPass string) promptResult {
	// Reserve vaultWriteReserve so a slow GUI prompt cannot push the run past the MDM timeout.
	ctx, cancel := withReserve(ctx, time.Hour, vaultWriteReserve)
	defer cancel()

	if ctx.Err() != nil {
		log.Println("[WARNING] No time left in the run budget for the GUI prompt; skipping it so the 1Password write completes.")
		logPromptReport(reportNoTime)
		return promptResult{outcome: passwordTimeout}
	}

	cmd := commandContext(ctx, toolSh, "-c", toolScutil+` <<< "show State:/Users/ConsoleUser" | `+toolAwk+` '/Name :/ && ! /loginwindow/ { print $3 }'`)
	out, err := cmd.Output()
	if err != nil {
		logPromptReport(reportNoUser)
		return promptResult{outcome: passwordUnavailable}
	}

	currentUser := strings.TrimSpace(string(out))
	if currentUser == "" || currentUser == "root" {
		log.Println("[WARNING] No standard user logged in. GUI prompt aborted.")
		logPromptReport(reportNoUser)
		return promptResult{outcome: passwordUnavailable}
	}

	if m.screenLocked(ctx) {
		log.Printf("[PROMPT SKIPPED: screen-locked] The screen of %s is locked. The prompt returns on the next check-in.\n", currentUser)
		logPromptReport(reportLocked)
		return promptResult{outcome: passwordTimeout, user: currentUser}
	}

	hasToken, err := m.secureTokenState(ctx, currentUser)
	if err != nil {
		log.Printf("[WARNING] Could not read the Secure Token state of the console user (%s): %v. Aborting GUI prompt.\n", currentUser, err)
		logPromptReport(reportUserNoToken)
		return promptResult{outcome: passwordUnavailable, user: currentUser}
	}
	if !hasToken {
		log.Printf("[WARNING] Current user (%s) lacks a Secure Token. Cannot grant. Aborting GUI prompt.\n", currentUser)
		logPromptReport(reportUserNoToken)
		return promptResult{outcome: passwordUnavailable, user: currentUser}
	}

	uidOut, err := commandContext(ctx, toolID, "-u", currentUser).Output()
	uid := strings.TrimSpace(string(uidOut))
	if err != nil || uid == "" {
		log.Printf("[WARNING] Could not resolve the uid of %s: %v. Aborting GUI prompt.\n", currentUser, err)
		logPromptReport(reportNoUser)
		return promptResult{outcome: passwordUnavailable, user: currentUser}
	}

	// opendirectoryd requires an admin credential for Secure Token grants. Start on the AbR step for standard users.
	needAdmin := !m.isAdminMember(ctx, currentUser)
	if needAdmin {
		if _, err := os.Stat(abrAppPath); err != nil {
			log.Printf("[WARNING] %s is not an administrator and Admin By Request is not installed — the token grant cannot succeed on this Mac.\n", currentUser)
			logPromptReport(reportNoAbR)
			return promptResult{outcome: passwordUnavailable, user: currentUser}
		}
	}

	outcome, tally := m.askPassword(ctx, uid, currentUser, needAdmin, func(ctx context.Context, userPass string) error {
		return m.grantSecureTokenSilently(ctx, targetUser, targetPass, currentUser, userPass)
	})
	return promptResult{outcome: outcome, user: currentUser, wrongPasswordRuns: tally.wrongPasswordRuns, windowFailedRuns: tally.windowFailedRuns, windowFailed: tally.windowFailed}
}

// openAppAsUser uses both launchctl asuser (Aqua session) and sudo -u (console user identity).
func openAppAsUser(ctx context.Context, uid, user, appName string) error {
	cmd := commandContext(ctx, toolLaunchctl, "asuser", uid, toolSudo, "-u", user, toolOpen, "-a", appName)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("[WARNING] Could not open app %q in %s's session: %v | output: %s\n", appName, user, err, strings.TrimSpace(string(out)))
		return err
	}
	return nil
}

func (m *MacOSManager) isAdminMember(ctx context.Context, user string) bool {
	out, err := commandContext(ctx, toolDsmemberutil, "checkmembership", "-U", user, "-G", "admin").CombinedOutput()
	return err == nil && strings.Contains(string(out), "user is a member")
}

func (m *MacOSManager) DeleteServiceAccountToken(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cmd := commandContext(ctx, toolSecurity, "delete-generic-password", "-l", "GoLAPS_Vault_Token", "/Library/Keychains/System.keychain")
	out, err := cmd.CombinedOutput()
	if err == nil {
		log.Println("[SECURITY] Removed leftover vault token from System Keychain.")
		return nil
	}
	if strings.Contains(string(out), "could not be found") {
		return nil
	}
	return fmt.Errorf("could not delete the keychain token: %w | output: %s", err, strings.TrimSpace(string(out)))
}
