//go:build darwin

package osmgmt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golaps/internal/password"
	"golaps/internal/version"
)

// supportURL returns the optional help link surfaced by the user-facing dialogs (env LAPS_SUPPORT_URL, e.g. your IT portal or the rollout announcement). Empty means the dialogs simply omit their help button.
func supportURL() string {
	return strings.TrimSpace(os.Getenv("LAPS_SUPPORT_URL"))
}

// Admin By Request client. The adminbyrequest:// URL scheme only activates the app (it carries no verbs — verified in the 5.2.2 binary), so it does NOT raise the "start an administrator session?" prompt. Relaunching the single-instance app with `open -a` is what surfaces that prompt, so we drive the app by name, not by URL.
const (
	abrAppPath = "/Applications/Admin By Request.app"
	abrAppName = "Admin By Request"

	// abrWaitWindow: how long we wait for the user to obtain admin rights via Admin By Request. An approved session shows up within ~10s of the user clicking, so this is only the walked-away ceiling. Deliberately short: a longer window parks the device's MDM script slot for the better part of an hour on a Mac whose user may never have seen the dialog, and the whole grant is retried on the next check-in anyway.
	abrWaitWindow = 15 * time.Minute
	// abrPollInterval bounds the pause between "AbR approved the session" and the password dialog appearing. dseditgroup -o checkmember is an instant local lookup, so polling every 2s costs nothing and cuts the perceived lag from up to 10s to up to 2s.
	abrPollInterval = 2 * time.Second

	// vaultWriteReserve is the slice of the run budget that no GUI interaction may eat into, so the vault write still fits after the token path gives up. Without it a dialog waiting on a human can push the run past the MDM's 60-minute kill and lose the rotated password entirely.
	vaultWriteReserve = 5 * time.Minute

	// dialogWait caps a single user-facing dialog (a human has to read and click).
	dialogWait = 5 * time.Minute
)

type SwiftPayload struct {
	Action     string `json:"action"`
	TargetUser string `json:"targetUser"`
	TargetPass string `json:"targetPass"`
	OldPass    string `json:"oldPass,omitempty"`
	AdminUser  string `json:"adminUser,omitempty"`
	AdminPass  string `json:"adminPass,omitempty"`
	// AllowAdminReset permits the helper's administrative reset. Set it ONLY for a token-less account: on a token holder that reset either reports a phantom success (sysadminctl exits 0 while opendirectoryd refuses) or silently breaks the SEP/FileVault chain, so the policy call belongs here, where the token state is known.
	AllowAdminReset bool `json:"allowAdminReset,omitempty"`
}

// changeOutcome mirrors ChangeOutcome in mac_helper.swift. The helper reports the failure CLASS; this side decides what to do about it.
type changeOutcome int

const (
	changeOK           changeOutcome = 0
	changeODError      changeOutcome = 1
	changeAuthFailed   changeOutcome = 2
	changeLocked       changeOutcome = 3
	changeResetRefused changeOutcome = 4
	// changePolicyRejected: OD 5402-5407 — the NEW password (or its timing) failed the device's password policy. The account is fine; recreating it cannot help and only churns a healthy admin.
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

// secrets returns every secret this payload carries, for scrubbing helper output before it is logged.
func (p SwiftPayload) secrets() []string {
	s := make([]string, 0, 3)
	for _, v := range []string{p.TargetPass, p.OldPass, p.AdminPass} {
		if v != "" {
			s = append(s, v)
		}
	}
	return s
}

// redactSecrets masks every known secret in text. The helper itself never interpolates a password into its [SWIFT] lines, but sysadminctl inherits the helper's stderr and OpenDirectory errors can echo the password back, so this scrubbing is a belt-and-suspenders precaution.
func redactSecrets(text string, secrets []string) string {
	for _, s := range secrets {
		text = strings.ReplaceAll(text, s, "[REDACTED]")
	}
	return text
}

// runner abstracts process execution so the account-repair ladder (heal/bridge/dscl) is testable; CombinedOutput semantics — a non-zero exit comes back as an error carrying ExitCode().
type runner interface {
	Run(ctx context.Context, stdin, name string, args ...string) ([]byte, error)
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, stdin, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	return cmd.CombinedOutput()
}

// exitCode extracts a process exit status from a runner error. ok=false means the process never ran or was killed by the context — callers must not read that as a verdict.
func exitCode(err error) (int, bool) {
	var ec interface{ ExitCode() int }
	if errors.As(err, &ec) {
		return ec.ExitCode(), true
	}
	return -1, false
}

type MacOSManager struct {
	run    runner
	sleep  func(time.Duration)                                        // injectable so the phantom-recovery tests don't spend real seconds in opendirectoryd settle waits
	prompt func(ctx context.Context, targetUser, newPass string) bool // the GUI/AbR token prompt; injectable because the real one drives osascript at the console
}

func NewManager() Manager {
	m := &MacOSManager{run: execRunner{}, sleep: time.Sleep}
	m.prompt = m.promptUserForToken
	return m
}

// withReserve derives a sub-context of at most want, while always leaving reserve of the run budget for the steps that follow. A non-positive remainder yields an already-expired context, so callers bail out instead of starting work they cannot finish.
func withReserve(ctx context.Context, want, reserve time.Duration) (context.Context, context.CancelFunc) {
	if deadline, ok := ctx.Deadline(); ok {
		if available := time.Until(deadline) - reserve; available < want {
			want = available
		}
	}
	return context.WithTimeout(ctx, want)
}

// runSwiftHelper executes the helper and returns its exit code. A non-zero code is a VERDICT, not a transport error — only a helper that could not run at all (or was killed by the run deadline) yields an error, because those two cases must not be read as "the password is wrong".
func (m *MacOSManager) runSwiftHelper(ctx context.Context, payload SwiftPayload) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	data, err := json.Marshal(payload)
	if err != nil {
		return -1, fmt.Errorf("failed to marshal JSON payload: %w", err)
	}

	out, err := m.run.Run(ctx, string(data), "/usr/local/bin/mac_helper")
	// The [SWIFT] lines are the only record of whether the rotation fell back to an administrative reset (i.e. whether the account may have lost its Secure Token), and since v1.2 they also carry sysadminctl's own refusal text — so they must be logged on success too, not only in the error.
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

func (m *MacOSManager) GetSystemInfo(ctx context.Context) (string, string) {
	log.Printf("[INFO] --- GoLAPS macOS Agent (Version: %s) --- \n", version.Version)

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "UnknownHost"
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ioreg", "-c", "IOPlatformExpertDevice", "-d", "2")
	output, err := cmd.Output()
	serial := "Unknown"

	if err == nil {
		re := regexp.MustCompile(`"IOPlatformSerialNumber" = "([^"]+)"`)
		matches := re.FindStringSubmatch(string(output))
		if len(matches) > 1 {
			serial = strings.TrimSpace(matches[1])
		}
	}
	return hostname, serial
}

// userAccountExists reports whether a local account exists. The error is deliberately separate from the bool: a failed *check* must never be read as "the account is missing", because that reading feeds the destructive auto-heal path below.
func (m *MacOSManager) userAccountExists(ctx context.Context, user string) (bool, error) {
	out, err := m.run.Run(ctx, "", "id", "-u", user)
	if err == nil {
		return true, nil
	}
	if ctx.Err() != nil {
		return false, fmt.Errorf("could not check whether %s exists: %w", user, ctx.Err())
	}
	if code, ok := exitCode(err); ok {
		// A non-zero exit is how `id` reports a missing account ("id: <user>: no such user").
		if !strings.Contains(string(out), "no such user") {
			log.Printf("[INFO] id -u %s exited %d: %s\n", user, code, strings.TrimSpace(string(out)))
		}
		return false, nil
	}
	return false, fmt.Errorf("could not run id -u %s: %w", user, err)
}

// EnsureUserAndChangePassword manages account existence and triggers native password rotation.
// IMPLEMENTS AGGRESSIVE AUTO-HEALING: If the user exists but lacks a token, it deletes the user to reset the SEP crypto-chain.
func (m *MacOSManager) EnsureUserAndChangePassword(ctx context.Context, user, oldPassword, altOldPass, newPassword string) error {
	// Account creation/deletion talks to opendirectoryd and can be slow; the run deadline still caps it.
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	// 1. Check if user exists
	userExists, err := m.userAccountExists(ctx, user)
	if err != nil {
		return err
	}

	// 2. Account missing entirely — create it and let ManageSecureToken grant the token afterwards.
	if !userExists {
		log.Printf("[WARNING] macOS user %s not found. Initiating Auto-Healing...\n", user)
		return m.createHiddenAdmin(ctx, user, "IT Admin", newPassword)
	}

	// Deleting an admin account is irreversible, so it must be driven by a definite answer from macOS. An errored check (timeout, hung opendirectoryd) used to be indistinguishable from "no token" and silently triggered the deletion — abort instead and let the MDM retry.
	hasToken, tokenErr := m.secureTokenState(ctx, user)
	if tokenErr != nil {
		return fmt.Errorf("refusing to auto-heal %s: could not determine its Secure Token state: %w", user, tokenErr)
	}

	// 3. No token: the SEP chain is already broken, so recreation costs nothing and fixes the crypto state.
	if !hasToken {
		return m.healAccount(ctx, user, newPassword)
	}

	// 4. Token holder, but OpenDirectory refuses to let it authenticate ("until password is changed"). Production forensics exhausted every soft repair — counter clear, legacy/per-user policy clears, MDM UnlockUserAccount, opendirectoryd restart, multiple reboots — the state is persistent on-disk/KDC, so recreation is the only cure. laps_token.sh runs those soft repairs before this binary, so reaching here blocked means they already failed.
	out, _ := m.run.Run(ctx, "", "pwpolicy", "-u", user, "authentication-allowed")
	if verdict := strings.TrimSpace(string(out)); strings.Contains(verdict, "not") && strings.Contains(verdict, "allowed") {
		log.Printf("[WARNING] %s holds a Secure Token but cannot authenticate (%s). Escalating to account recreation — the token grant afterwards may prompt the console user via Admin By Request.\n", user, verdict)
		return m.healAccount(ctx, user, newPassword)
	}

	// 5. Rotate. AllowAdminReset stays false for a token holder: sysadminctl's reset would either exit 0 while opendirectoryd refused (escrowing a password the device never took — observed in production) or succeed while leaving the SEP-wrapped volume key behind, which shows as ENABLED but no longer unlocks FileVault at preboot.
	log.Printf("[INFO] User %s found with intact Secure Token. Delegating password reset to Swift Helper...", user)

	outcome, err := m.runSwiftHelper(ctx, SwiftPayload{
		Action:          "change_password",
		TargetUser:      user,
		TargetPass:      newPassword,
		OldPass:         oldPassword,
		AllowAdminReset: false,
	})
	if err != nil {
		return fmt.Errorf("failed to change password natively: %w", err)
	}

	// The two vault copies (staged pending and recorded) can each be the live one depending on where the previous run died — a fleet-wide rollout produced both shapes via vault write contention. Trying the second candidate costs one helper call; recreation costs the Secure Token and a user prompt.
	if changeOutcome(outcome) == changeAuthFailed && altOldPass != "" && altOldPass != oldPassword {
		log.Printf("[INFO] The primary password candidate for %s no longer authenticates; trying the alternate one before escalating to recreation.\n", user)
		outcome, err = m.runSwiftHelper(ctx, SwiftPayload{
			Action:          "change_password",
			TargetUser:      user,
			TargetPass:      newPassword,
			OldPass:         altOldPass,
			AllowAdminReset: false,
		})
		if err != nil {
			return fmt.Errorf("failed to change password natively: %w", err)
		}
		if changeOutcome(outcome) == changeOK {
			log.Printf("[SUCCESS] The alternate password candidate was the live one — rotation completed without recreation.\n")
		}
	}

	switch changeOutcome(outcome) {
	case changeOK:
		return nil
	case changeAuthFailed, changeLocked:
		// The recorded password no longer opens the account. Recreation is the honest cure: an administrative reset here is exactly the phantom/FileVault risk described above, and it is what hid this state behind a green PASS for weeks.
		log.Printf("[WARNING] %s holds a Secure Token but the recorded password no longer authenticates (%s). Escalating to account recreation rather than an administrative reset.\n", user, changeOutcome(outcome))
		return m.healAccount(ctx, user, newPassword)
	case changePolicyRejected:
		// The account is healthy — the generated password lost to the device's password policy. Recreation would destroy a working admin over a dice roll; the next run generates a fresh password.
		return fmt.Errorf("the device's password policy rejected the generated password for %s (OD 5402-5407): %w — not recreating a healthy account; the next run retries with a new password", user, ErrPolicyRejected)
	default:
		return fmt.Errorf("rotating the password for %s failed (%s)", user, changeOutcome(outcome))
	}
}

// healAccount deletes and recreates the target admin, bridging macOS's last-admin guard with a temporary bridge admin when the target is the only admin left. It always ends with the account recreated under newPassword; the Secure Token grant happens later, in ManageSecureToken (which may prompt the console user via Admin By Request).
func (m *MacOSManager) healAccount(ctx context.Context, user, newPassword string) error {
	log.Printf("[WARNING] User %s exists but is unusable (no token, or locked beyond repair). Deleting account to heal crypto-chain...\n", user)

	if out, err := m.run.Run(ctx, "", "sysadminctl", "-deleteUser", user); err != nil {
		log.Printf("[WARNING] sysadminctl -deleteUser %s failed: %v | output: %s\n", user, err, strings.TrimSpace(string(out)))
	}
	// NEVER fall back to a raw `dscl . -delete` here: it bypasses macOS's last-admin guard, deletes only the directory record and orphans the SEP identity / LKDC principal — after which sysadminctl -addUser for the same name exits 0 without creating anything, forever (a create-phantom state observed in production).
	stillThere, err := m.userAccountExists(ctx, user)
	if err != nil {
		return err
	}
	if !stillThere {
		return m.createHiddenAdmin(ctx, user, "IT Admin", newPassword)
	}

	// sysadminctl refused — on AbR-managed Macs the humans are demoted, so the target IS the last admin. Bridge the constraint: a second admin (no Secure Token needed, the guard counts admins) makes the target deletable the supported way.
	log.Printf("[WARNING] %s survived deletion — it is likely the last admin (Admin By Request demotes the humans). Creating a temporary bridge admin...\n", user)
	return m.withBridgeAdmin(ctx, user, func() error {
		if out, err := m.run.Run(ctx, "", "sysadminctl", "-deleteUser", user); err != nil {
			log.Printf("[WARNING] sysadminctl -deleteUser %s (with bridge) failed: %v | output: %s\n", user, err, strings.TrimSpace(string(out)))
		}
		// userAccountExists answers "does it exist" — reading it as "is it gone" inverted this check and made every successful last-admin deletion abort before the recreate, leaving the bridge as the device's only admin (caught by TestHealAccountBridgesLastAdminGuard; the bridge path had never fired live).
		stillExists, err := m.userAccountExists(ctx, user)
		if err != nil {
			return err
		}
		if stillExists {
			return fmt.Errorf("could not delete %s even with a bridge admin present: the account still exists", user)
		}
		log.Printf("[INFO] %s deleted with the bridge admin holding the admin count. Recreating it inside the bridge window...\n", user)
		// Recreate INSIDE the bridge window, so a failure here can never leave the device with no admin at all.
		return m.createHiddenAdmin(ctx, user, "IT Admin", newPassword)
	})
}

// createHiddenAdmin creates a hidden local admin and verifies it really exists afterwards.
func (m *MacOSManager) createHiddenAdmin(ctx context.Context, name, fullName, pass string) error {
	addUser := func() error {
		out, err := m.run.Run(ctx, pass+"\n", "sysadminctl", "-addUser", name, "-fullName", fullName, "-password", "-", "-admin")
		// Log the output even on exit 0: sysadminctl reports its real failures there while still exiting clean, and this line is the only fleet-wide window into WHY a create-phantom happens. The password travels via stdin, so the output carries no secret.
		if o := redactSecrets(strings.TrimSpace(string(out)), []string{pass}); o != "" {
			log.Printf("[INFO] sysadminctl -addUser %s output: %s\n", name, o)
		}
		if err != nil {
			return fmt.Errorf("failed to create %s: %w | output: %s", name, err, strings.TrimSpace(string(out)))
		}
		if out, err := m.run.Run(ctx, "", "dscl", ".", "create", "/Users/"+name, "IsHidden", "1"); err != nil {
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
	if out, err := m.run.Run(ctx, "", "odutil", "reset", "cache"); err != nil {
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
		// Last resort: root assembles the record directly through dscl, bypassing sysadminctl entirely. Unlike sysadminctl this path fails LOUDLY (eDSRecordAlreadyExists names a tombstone record, etc.), so even its failure finally says WHY the account cannot exist.
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

// createAdminViaDscl assembles a hidden local admin record attribute by attribute, as root. `dscl . -passwd` cannot read from stdin, so the record is first sealed with a THROWAWAY password (that one does appear in argv) and immediately rotated to the real password through the Swift helper over stdin — the real password never touches a process argument list, and the throwaway is dead by the time any observer reads it.
func (m *MacOSManager) createAdminViaDscl(ctx context.Context, name, fullName, pass string) error {
	// Pick the first free UID at or above 501.
	out, err := m.run.Run(ctx, "", "dscl", ".", "-list", "/Users", "UniqueID")
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

	throwaway, err := password.Generate(0)
	if err != nil {
		return fmt.Errorf("could not generate a throwaway password: %w", err)
	}

	steps := [][]string{
		{"-create", "/Users/" + name},
		{"-create", "/Users/" + name, "UserShell", "/bin/zsh"},
		{"-create", "/Users/" + name, "RealName", fullName},
		{"-create", "/Users/" + name, "UniqueID", strconv.Itoa(uid)},
		{"-create", "/Users/" + name, "PrimaryGroupID", "20"},
		{"-create", "/Users/" + name, "NFSHomeDirectory", "/Users/" + name},
		{"-create", "/Users/" + name, "IsHidden", "1"},
		{"-passwd", "/Users/" + name, throwaway},
	}
	for _, args := range steps {
		if out, err := m.run.Run(ctx, "", "dscl", append([]string{"."}, args...)...); err != nil {
			return fmt.Errorf("dscl %s failed: %w | %s", args[0]+" "+args[1], err, redactSecrets(strings.TrimSpace(string(out)), []string{throwaway}))
		}
	}
	if out, err := m.run.Run(ctx, "", "dseditgroup", "-o", "edit", "-a", name, "-t", "user", "admin"); err != nil {
		return fmt.Errorf("could not add %s to the admin group: %w | %s", name, err, strings.TrimSpace(string(out)))
	}

	// Rotate throwaway -> real over stdin. The account was created seconds ago and provably holds no Secure Token, so the administrative reset is safe here as a fallback — this is the one place AllowAdminReset is legitimately true.
	if err := m.callSwiftHelper(ctx, SwiftPayload{
		Action:          "change_password",
		TargetUser:      name,
		TargetPass:      pass,
		OldPass:         throwaway,
		AllowAdminReset: true,
	}); err != nil {
		return fmt.Errorf("account %s built via dscl, but rotating the throwaway password failed (the account is left with an unknown password; the next run's auto-heal recycles it): %w", name, err)
	}
	log.Printf("[INFO] %s built via dscl (UID %d), added to the admin group, real password set over stdin.\n", name, uid)
	m.sleep(2 * time.Second)
	return nil
}

// legacyBridgeAdmin is the temporary second admin used to satisfy macOS's last-admin guard. On devices migrated from a previous MDM the same account may already exist, so bridging reuses it instead of creating anything, and any leftover is later removed by laps_token.sh's own legacy-admin cleanup once the target holds a Secure Token.
const legacyBridgeAdmin = "laps-bridge"

// withBridgeAdmin runs fn while a second admin keeps the admin count above one, so macOS's last-admin guard cannot refuse deleting the target. The bridge needs no Secure Token — the guard counts admins, not token holders.
func (m *MacOSManager) withBridgeAdmin(ctx context.Context, targetUser string, fn func() error) error {
	bridge := legacyBridgeAdmin

	if exists, err := m.userAccountExists(ctx, bridge); err != nil {
		return err
	} else if !exists {
		bridgePass, err := password.Generate(0) // 0 -> generator default length; the bridge is never authenticated as, the password exists only because -addUser requires one
		if err != nil {
			return fmt.Errorf("could not generate a password for the bridge admin: %w", err)
		}
		if err := m.createHiddenAdmin(ctx, bridge, "IT Recovery Bridge", bridgePass); err != nil {
			return fmt.Errorf("could not create the bridge admin %s: %w", bridge, err)
		}
	} else {
		log.Printf("[INFO] Reusing the existing %s account as the bridge admin.\n", bridge)
	}

	fnErr := fn()

	// Cleanup. Refuse to delete the bridge while the target is absent: that would remove the device's only admin.
	if targetThere, err := m.userAccountExists(ctx, targetUser); err != nil || !targetThere {
		log.Printf("[ERROR] Keeping bridge admin %s: the target %s is missing and the bridge is the only admin left (check err: %v). The next run will reuse and then remove it.\n", bridge, targetUser, err)
		return fnErr
	}
	// A bridge account that HOLDS a Secure Token may be the device's only token holder, and the freshly recreated target has no token yet — keep it and let laps_token.sh remove it once the target's token is granted (its cleanup already checks exactly that).
	if hasToken, err := m.secureTokenState(ctx, bridge); err != nil || hasToken {
		log.Printf("[INFO] Keeping %s for now (Secure Token state: enabled=%v, err=%v). laps_token.sh removes it once %s holds a token.\n", bridge, hasToken, err, targetUser)
		return fnErr
	}
	if out, err := m.run.Run(ctx, "", "sysadminctl", "-deleteUser", bridge); err != nil {
		log.Printf("[WARNING] sysadminctl -deleteUser %s failed: %v | output: %s\n", bridge, err, strings.TrimSpace(string(out)))
	}
	if still, err := m.userAccountExists(ctx, bridge); err == nil && still {
		log.Printf("[WARNING] Bridge admin %s could not be removed this run — laps_token.sh's legacy-admin cleanup will retire it once %s holds a Secure Token.\n", bridge, targetUser)
	}
	return fnErr
}

func (m *MacOSManager) ManageSecureToken(ctx context.Context, targetUser, newPass string, availableCreds map[string]string) string {
	// An errored check is NOT "no token" — but here the safe reading is the opposite one from the auto-heal path: carry on into the grant attempts, which verify the real state afterwards, rather than declaring a token that may well be present.
	if hasToken, err := m.secureTokenState(ctx, targetUser); err != nil {
		log.Printf("[WARNING] Could not read the Secure Token state of %s (%v). Continuing as if it had none; the grant path verifies the result.\n", targetUser, err)
	} else if hasToken {
		log.Printf("[SUCCESS] Verified: %s already has an active Secure Token.\n", targetUser)
		return "ENABLED (Auto-Migrated or Existing)"
	}

	log.Printf("[INFO] Verified: %s lacks a Secure Token. Scanning macOS for token holders...\n", targetUser)

	tokenHolders := m.getTokenHolders(ctx)

	for _, admin := range tokenHolders {
		log.Printf("[INFO] Evaluating token holder candidate: %s\n", admin)

		if adminPass, ok := availableCreds[admin]; ok {
			log.Printf("[INFO] -> Attempt 1: Trying the vault-recorded password for %s...\n", admin)

			grantErr := m.grantSecureTokenSilently(ctx, targetUser, newPass, admin, adminPass)
			if grantErr == nil {
				log.Printf("[SUCCESS] Secure Token granted silently via %s.\n", admin)
				return "ENABLED (Silent - Vault)"
			}
			log.Printf("[WARNING] The vault-recorded password failed for %s. Details: %v\n", admin, grantErr)
		}

		// MDM_FALLBACK_PASS is the legacy *service* admin's password. Trying it against a human account can never succeed and only buries the log in -14090 "Operation is not permitted without secure token unlock" noise that reads like a rights problem.
		if !isServiceAccount(admin, targetUser, availableCreds) {
			log.Printf("[INFO] -> Skipping MDM Legacy Password for %s: not an IT-managed service account.\n", admin)
			continue
		}

		if mdmPass, ok := availableCreds["MDM_FALLBACK_PASS"]; ok {
			log.Printf("[INFO] -> Attempt 2: Trying MDM Legacy Password for %s...\n", admin)

			grantErr := m.grantSecureTokenSilently(ctx, targetUser, newPass, admin, mdmPass)
			if grantErr == nil {
				log.Printf("[SUCCESS] Secure Token granted silently via %s (MDM Fallback).\n", admin)
				return "ENABLED (Silent - MDM)"
			}
			log.Printf("[WARNING] MDM Password failed for %s. Details: %v\n", admin, grantErr)
		}
	}

	log.Println("[WARNING] All silent grant attempts failed or no matching passwords found. Triggering GUI Prompt...")
	if m.prompt(ctx, targetUser, newPass) {
		return "ENABLED (Via GUI Prompt)"
	}

	// The prompt failed, so the token stays missing this run — the grant retries on every check-in until it lands; a tokenless service admin is never an accepted end state. Coverage decides only how the failure REPORTS: with an escrowed PRK + bootstrap token the device is degraded (IT unlocks preboot via PRK once), not unrecoverable, so it should not sit permanently red in the MDM console.
	if m.recoveryCoveredByMDM(ctx) {
		log.Printf("[WARNING] %s still holds no Secure Token after the prompt, but the device has a personal recovery key and an escrowed bootstrap token — reporting a covered degradation instead of a failure; the grant retries on the next run.\n", targetUser)
		return TokenStatusDisabledCovered
	}

	return "DISABLED (Review Required)"
}

// recoveryCoveredByMDM reports whether losing the service admin's Secure Token still leaves MDM a FileVault recovery path: a personal recovery key exists locally AND the bootstrap token is escrowed. Both checks fail closed — an error or unrecognised output reads as "not covered", which keeps the honest red status.
func (m *MacOSManager) recoveryCoveredByMDM(ctx context.Context) bool {
	// This runs AFTER the GUI prompt, i.e. inside the budget reserved for the vault write — a wedged fdesetup/profiles must time out here, never eat the vault reserve.
	ctx, cancel := withReserve(ctx, 20*time.Second, vaultWriteReserve)
	defer cancel()
	out, err := m.run.Run(ctx, "", "fdesetup", "haspersonalrecoverykey")
	if err != nil || !strings.EqualFold(strings.TrimSpace(string(out)), "true") {
		log.Printf("[INFO] No usable personal recovery key (fdesetup: %q, err: %v) — MDM cannot recover FileVault without the service admin.\n", strings.TrimSpace(string(out)), err)
		return false
	}
	out, err = m.run.Run(ctx, "", "profiles", "status", "-type", "bootstraptoken")
	if err != nil || !bootstrapTokenEscrowed(string(out)) {
		log.Printf("[INFO] Bootstrap token is not escrowed (profiles: %q, err: %v).\n", strings.TrimSpace(string(out)), err)
		return false
	}
	return true
}

// bootstrapTokenEscrowed parses `profiles status -type bootstraptoken`; the affirmative output ends with "Bootstrap Token escrowed to server: YES".
func bootstrapTokenEscrowed(output string) bool {
	return strings.Contains(strings.ToLower(output), "escrowed to server: yes")
}

// isServiceAccount reports whether login is one of the IT-managed admin accounts that the legacy MDM password could plausibly belong to.
func isServiceAccount(login, targetUser string, availableCreds map[string]string) bool {
	if login == targetUser || login == legacyBridgeAdmin {
		return true
	}
	_, known := availableCreds[login]
	return known
}

// parseSecureTokenStatus turns `sysadminctl -secureTokenStatus` output into a definite answer. It returns ok=false when macOS said neither ENABLED nor DISABLED, so the caller can tell "this account has no token" apart from "the question was never answered".
func parseSecureTokenStatus(output string) (enabled, ok bool) {
	// Match the whole phrase — a bare "ENABLED" test is one typo from matching "DISABLED".
	switch {
	case strings.Contains(output, "is ENABLED"), strings.Contains(output, "is ON"):
		return true, true
	case strings.Contains(output, "is DISABLED"), strings.Contains(output, "is OFF"):
		return false, true
	}
	return false, false
}

// secureTokenState reports whether user holds a Secure Token.
// A returned error means macOS did not answer (timeout, hung opendirectoryd, unknown account, unrecognised output) — it does NOT mean the account has no token, and callers must not treat it as such. Reporting a failed check as "no token" is what made a transient sysadminctl failure delete a healthy admin account.
func (m *MacOSManager) secureTokenState(ctx context.Context, user string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	out, err := m.run.Run(ctx, "", "sysadminctl", "-secureTokenStatus", user)
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

// verifyUserPassword checks a login password through the Swift helper (OpenDirectory verifyPassword over the existing stdin channel). It replaces `dscl . -authonly <user> <password>`, which put the console user's own login password in argv — visible to root-level observers, EDR exec telemetry and sysdiagnose, and in direct contradiction with this project's "no credentials on command lines" rule.
func (m *MacOSManager) verifyUserPassword(ctx context.Context, user, pass string) bool {
	if err := m.callSwiftHelper(ctx, SwiftPayload{
		Action:     "verify_password",
		TargetUser: user,
		TargetPass: pass,
	}); err != nil {
		log.Printf("[INFO] Password verification for %s did not pass: %v\n", user, err)
		return false
	}
	return true
}

// getTokenHolders returns every local account that actually holds a Secure Token.
// It deliberately no longer uses `fdesetup list`: that reports FileVault-*enabled* users, which is a different set. On a Mac where FileVault has not finished enabling, real token holders are missing from it, the list comes back empty, and the old code then fell back to a hardcoded legacy admin — the very account laps_token.sh deletes once the target admin is healthy. The silent grant path then had no credential it could possibly use.
func (m *MacOSManager) getTokenHolders(ctx context.Context) []string {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	var holders []string

	out, err := m.run.Run(ctx, "", "dscl", ".", "-list", "/Users", "UniqueID")
	if err != nil {
		log.Printf("[WARNING] Could not enumerate local users: %v\n", err)
	} else {
		for _, name := range parseLocalUsers(string(out)) {
			enabled, err := m.secureTokenState(ctx, name)
			if err != nil {
				// Say so rather than dropping the account silently: a candidate holder lost to a timeout is a credential the silent grant path will never get to try.
				log.Printf("[WARNING] Skipping %s as a token-holder candidate: %v\n", name, err)
				continue
			}
			if enabled {
				holders = append(holders, name)
			}
		}
	}

	if len(holders) == 0 {
		log.Println("[WARNING] No Secure Token holder found among local accounts. Falling back to the legacy bridge admin.")
		holders = append(holders, legacyBridgeAdmin)
	}

	return holders
}

// parseLocalUsers extracts real (non-system) account names from `dscl . -list /Users UniqueID`.
// Accounts with UID < 500 are skipped so we don't spawn ~100 sysadminctl calls on system users.
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

func (m *MacOSManager) promptUserForToken(ctx context.Context, targetUser, targetPass string) bool {
	// Everything below waits on a human. Cap it so the vault write that follows still fits inside the run budget instead of being hard-killed by the MDM at 60 minutes.
	ctx, cancel := withReserve(ctx, time.Hour, vaultWriteReserve)
	defer cancel()

	if ctx.Err() != nil {
		log.Println("[WARNING] No time left in the run budget for the GUI prompt; skipping it so the vault write completes.")
		return false
	}

	cmd := exec.CommandContext(ctx, "sh", "-c", `scutil <<< "show State:/Users/ConsoleUser" | awk '/Name :/ && ! /loginwindow/ { print $3 }'`)
	out, err := cmd.Output()
	if err != nil {
		return false
	}

	currentUser := strings.TrimSpace(string(out))
	if currentUser == "" || currentUser == "root" {
		log.Println("[WARNING] No standard user logged in. GUI prompt aborted.")
		return false
	}

	hasToken, err := m.secureTokenState(ctx, currentUser)
	if err != nil {
		log.Printf("[WARNING] Could not read the Secure Token state of the console user (%s): %v. Aborting GUI prompt.\n", currentUser, err)
		return false
	}
	if !hasToken {
		log.Printf("[WARNING] Current user (%s) lacks a Secure Token. Cannot grant. Aborting GUI prompt.\n", currentUser)
		return false
	}

	uidOut, err := exec.CommandContext(ctx, "id", "-u", currentUser).Output()
	uid := strings.TrimSpace(string(uidOut))
	if err != nil || uid == "" {
		// Without a uid every `launchctl asuser` below fails instantly, burning the attempt loop in a fast spin and showing the user nothing.
		log.Printf("[WARNING] Could not resolve the uid of %s: %v. Aborting GUI prompt.\n", currentUser, err)
		return false
	}

	// opendirectoryd only accepts the grant when the authenticating credential is an administrator (refusal 5101 "Credential is not an admin" otherwise), and Admin By Request removes standing admin rights — so on an AbR-managed Mac a standard user's correct password still cannot succeed. Detect that BEFORE asking for the password and walk the user through obtaining a temporary admin session first.
	if !m.isAdminMember(ctx, currentUser) && !m.ensureAdminViaAbR(ctx, uid, currentUser) {
		return false
	}

	// Two separate bounds: wrong passwords consume an attempt, everything else (following the help link, dismissing the dialog) does not — but the dialog count still caps the loop so a dialog that keeps erroring cannot spin forever.
	const maxAttempts = 5
	const maxDialogs = 15

	attempt := 1
	for dialogs := 0; attempt <= maxAttempts && dialogs < maxDialogs; dialogs++ {
		script := m.generateAppleScript(attempt, maxAttempts)

		asCmd := exec.CommandContext(ctx, "launchctl", "asuser", uid, "osascript")
		asCmd.Stdin = strings.NewReader(script)
		asOut, err := asCmd.Output()

		if err != nil {
			log.Printf("[WARNING] osascript execution failed or timed out: %v", err)
			return false
		}

		result := strings.TrimSpace(string(asOut))

		if result == "OPEN_HELP" {
			if url := supportURL(); url != "" {
				openURLAsUser(ctx, uid, currentUser, url)
			}
			continue
		}
		if result == "ESCAPED" {
			continue
		}
		if !strings.HasPrefix(result, "UPDATE::") {
			continue
		}

		userPass := strings.TrimPrefix(result, "UPDATE::")
		if userPass == "" {
			continue
		}

		if !m.verifyUserPassword(ctx, currentUser, userPass) {
			log.Printf("[WARNING] Incorrect password entered in GUI (Attempt %d).\n", attempt)
			attempt++
			continue
		}

		log.Println("[INFO] Valid GUI password received. Delegating grant to Swift Helper...")

		grantErr := m.grantSecureTokenSilently(ctx, targetUser, targetPass, currentUser, userPass)

		// The AbR session can expire between the pre-check and the grant (or the pre-check passed on a session with seconds left). If the refusal is the admin-membership one, walk the user through AbR and retry the same already-validated password once instead of failing with a generic error.
		if grantErr != nil && !m.isAdminMember(ctx, currentUser) {
			log.Printf("[WARNING] Grant refused because %s is not an administrator (Admin By Request rights expired?). Offering an AbR session and retrying...\n", currentUser)
			if m.ensureAdminViaAbR(ctx, uid, currentUser) {
				grantErr = m.grantSecureTokenSilently(ctx, targetUser, targetPass, currentUser, userPass)
			}
		}

		if grantErr != nil {
			log.Printf("[ERROR] Swift token grant failed: %v\n", grantErr)
			m.showErrorMessage(ctx, currentUser, uid)
			return false
		}

		successScript := `display dialog "Thank you!" & return & return & "The IT security update has been completed successfully. You can now close this window." buttons {"OK"} default button "OK" with title "GoLAPS - Success" with icon note`
		successCtx, cancelSuccess := withReserve(ctx, dialogWait, vaultWriteReserve)
		successCmd := exec.CommandContext(successCtx, "launchctl", "asuser", uid, "osascript")
		successCmd.Stdin = strings.NewReader(successScript)
		if err := successCmd.Run(); err != nil {
			log.Printf("[INFO] Success dialog was not shown or was dismissed: %v\n", err)
		}
		cancelSuccess()
		log.Println("[SUCCESS] GUI Token Grant Successful!")
		return true
	}

	m.showFailureMessage(ctx, currentUser, uid)
	return false
}

// openURLAsUser opens a URL in the console user's GUI session, as that user.
// BOTH parts are required, and each one alone is broken:
//   - `launchctl asuser <uid>` puts the process in the user's Aqua/bootstrap session, which `open` needs to have a GUI session to hand the URL to — but it does NOT change the uid. The process stays root, so LaunchServices resolves the default browser from *root's* preferences, where none is set, and silently falls back to Safari. Observed in production: with asuser-only the URL opened in Safari with no logged-in session instead of the user's actual default browser.
//   - `sudo -u <user>` alone drops to the user (so LaunchServices reads their default-browser preference and the browser starts with their profile and cookies) but does not enter the Aqua session.
//
// Combined, the URL lands in the user's real default browser with their existing session, so a help link resolves without a second sign-in. Running sudo from root needs no password, and Admin By Request's per-session sudo gating applies to non-root callers, not to us.
func openURLAsUser(ctx context.Context, uid, user, url string) {
	cmd := exec.CommandContext(ctx, "launchctl", "asuser", uid, "sudo", "-u", user, "open", url)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("[WARNING] Could not open %s in %s's session: %v | output: %s\n", url, user, err, strings.TrimSpace(string(out)))
	}
}

// openAppAsUser launches (or, for a single-instance app, re-activates) a GUI app in the console user's session. Same launchctl-asuser + sudo -u pairing as openURLAsUser and for the same reason. Used to raise Admin By Request's "start an administrator session?" prompt, which the adminbyrequest:// URL scheme does not do on its own.
func openAppAsUser(ctx context.Context, uid, user, appName string) error {
	cmd := exec.CommandContext(ctx, "launchctl", "asuser", uid, "sudo", "-u", user, "open", "-a", appName)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("[WARNING] Could not open app %q in %s's session: %v | output: %s\n", appName, user, err, strings.TrimSpace(string(out)))
		return err
	}
	return nil
}

// isAdminMember reports whether user is currently in the local admin group — the exact property opendirectoryd checks on the authenticating credential before it will enable a SEP credential (its refusal is error 5101 "Credential is not an admin").
func (m *MacOSManager) isAdminMember(ctx context.Context, user string) bool {
	out, err := exec.CommandContext(ctx, "dsmemberutil", "checkmembership", "-U", user, "-G", "admin").CombinedOutput()
	return err == nil && strings.Contains(string(out), "user is a member")
}

// ensureAdminViaAbR guides the console user into a temporary Admin By Request session and waits until their admin rights actually appear. Returns true once the user is an admin.
// This exists because the GUI grant path is otherwise a dead end on AbR-managed Macs: the user's password is correct, but without admin membership opendirectoryd refuses the grant, and the user only saw a generic "unexpected system error". The observed manual fix was an IT person telling them to request AbR access and try again — this automates that.
func (m *MacOSManager) ensureAdminViaAbR(ctx context.Context, uid, user string) bool {
	if _, err := os.Stat(abrAppPath); err != nil {
		log.Printf("[WARNING] %s is not an administrator and Admin By Request is not installed — the token grant cannot succeed on this Mac.\n", user)
		return false
	}

	log.Printf("[INFO] %s is not an administrator (Admin By Request manages rights on this Mac). Asking the user to request a temporary admin session...\n", user)

	// No Cancel button, by design — the same as the password prompt. The update cannot proceed without admin rights, so the only ways out are "get admin" or the wait-window timeout. Escape (osascript "on error") is therefore NOT a cancel: we open Admin By Request anyway.
	helpButton := ""
	if supportURL() != "" {
		helpButton = `"Open Help", `
	}
	abrScript := fmt.Sprintf(`
	try
		set dialogText to "Your organization is finishing a security update, and it needs you to hold temporary administrator rights for a moment.\n\nClick \"Open Admin By Request\", choose Request administrator access, confirm with Yes, and leave this window — it continues automatically once access is granted.\n\nIf you want to verify this request, contact your IT support team."
		set result to display dialog dialogText buttons {%s"Open Admin By Request"} default button "Open Admin By Request" with title "GoLAPS - Admin Access Needed" with icon caution
		return button returned of result
	on error
		return "ESCAPED"
	end try`, helpButton)

	dialogCtx, cancelDialog := withReserve(ctx, dialogWait, vaultWriteReserve)
	abrCmd := exec.CommandContext(dialogCtx, "launchctl", "asuser", uid, "osascript")
	abrCmd.Stdin = strings.NewReader(abrScript)
	abrOut, abrErr := abrCmd.Output()
	cancelDialog()

	if abrErr != nil {
		// The dialog never reached the user (no GUI session, osascript blocked, budget gone). Waiting out the poll window here would park the device's MDM script slot on a prompt nobody ever saw, so give up now and retry on the next check-in.
		log.Printf("[WARNING] Could not show the Admin By Request prompt to %s: %v. Not waiting for an admin session.\n", user, abrErr)
		return false
	}

	if strings.TrimSpace(string(abrOut)) == "Open Help" {
		if url := supportURL(); url != "" {
			openURLAsUser(ctx, uid, user, url)
		}
	}
	// Every path leads here: raise Admin By Request's session prompt and wait. `open -a` re-activates the single-instance agent, which surfaces its "start an administrator session?" window — the URL scheme alone does not.
	if err := openAppAsUser(ctx, uid, user, abrAppName); err != nil {
		log.Printf("[WARNING] Admin By Request could not be raised for %s; not waiting for an admin session.\n", user)
		return false
	}

	// Poll until the AbR approval lands ("Added user to admin group" in its log). Approval can involve a human, so we wait a while; ctx still caps the whole interaction.
	waitCtx, cancelWait := withReserve(ctx, abrWaitWindow, vaultWriteReserve)
	defer cancelWait()

	for waitCtx.Err() == nil {
		select {
		case <-waitCtx.Done():
		case <-time.After(abrPollInterval):
		}
		if m.isAdminMember(ctx, user) {
			log.Printf("[SUCCESS] %s obtained admin rights via Admin By Request. Continuing.\n", user)
			return true
		}
	}

	log.Printf("[WARNING] %s did not obtain admin rights within %s. Grant aborted; will retry on the next MDM check-in.\n", user, abrWaitWindow)
	return false
}

// showErrorMessage reports a failed grant. Like the password prompt, it offers a clickable help route when LAPS_SUPPORT_URL is set: a plain-text pointer behind a lone OK button leaves the user nothing to click and nowhere to verify the request.
func (m *MacOSManager) showErrorMessage(ctx context.Context, currentUser, uid string) {
	// A dialog waits for a human, so it gets a generous cap — but never at the cost of the vault write still queued behind it.
	ctx, cancel := withReserve(ctx, dialogWait, vaultWriteReserve)
	defer cancel()

	helpButton := ""
	defaultButton := "OK"
	if supportURL() != "" {
		helpButton = `"Open Help", `
		defaultButton = "Open Help"
	}
	errScript := fmt.Sprintf(`
	try
		set dialogText to "An unexpected system error occurred while applying the security update." & return & return & "Please contact your IT support team."
		set result to display dialog dialogText buttons {%s"OK"} default button "%s" with title "GoLAPS - Error" with icon caution
		return button returned of result
	on error
		return "CANCELLED"
	end try`, helpButton, defaultButton)

	errCmd := exec.CommandContext(ctx, "launchctl", "asuser", uid, "osascript")
	errCmd.Stdin = strings.NewReader(errScript)
	errOut, _ := errCmd.Output()

	if strings.TrimSpace(string(errOut)) == "Open Help" {
		if url := supportURL(); url != "" {
			openURLAsUser(ctx, uid, currentUser, url)
		}
	}
}

func (m *MacOSManager) showFailureMessage(ctx context.Context, currentUser, uid string) {
	ctx, cancel := withReserve(ctx, dialogWait, vaultWriteReserve)
	defer cancel()

	helpButton := ""
	defaultButton := "OK"
	if supportURL() != "" {
		helpButton = `"Open Help", `
		defaultButton = "Open Help"
	}
	failScript := fmt.Sprintf(`
	try
		set dialogText to "It looks like you may have forgotten your Mac login password.\n\nThis security update cannot proceed. Please contact your IT support team for assistance."
		set result to display dialog dialogText buttons {%s"OK"} default button "%s" with title "GoLAPS - Update Failed" with icon stop
		return button returned of result
	on error
		return "CANCELLED"
	end try`, helpButton, defaultButton)

	failCmd := exec.CommandContext(ctx, "launchctl", "asuser", uid, "osascript")
	failCmd.Stdin = strings.NewReader(failScript)
	failOut, _ := failCmd.Output()

	if strings.TrimSpace(string(failOut)) == "Open Help" {
		if url := supportURL(); url != "" {
			openURLAsUser(ctx, uid, currentUser, url)
		}
	}
}

func (m *MacOSManager) generateAppleScript(attempt, maxAttempts int) string {
	var dialogText string
	if attempt == 1 {
		dialogText = "Your organization is updating macOS security configurations.\\n\\nWe are deploying a new background IT account to help with FileVault data recovery. To complete this automated process, macOS requires your local login password.\\n\\nIf you want to verify this request, contact your IT support team.\\n\\nPlease enter your Mac login password to proceed:"
	} else {
		dialogText = fmt.Sprintf("Incorrect password. Please try again. (Attempt %d of %d)\\n\\nReminder: this is a verified IT update — contact your IT support team to confirm.\\n\\nPlease enter your Mac login password:", attempt, maxAttempts)
	}

	buttons := `{"Update"}`
	if supportURL() != "" {
		buttons = `{"Open Help", "Update"}`
	}

	return fmt.Sprintf(`
	try
		set dialogText to "%s"
		set result to display dialog dialogText default answer "" with hidden answer buttons %s default button "Update" with title "GoLAPS - Security Update" with icon caution

		if button returned of result is "Open Help" then
			return "OPEN_HELP"
		else
			return "UPDATE::" & text returned of result
		end if
	on error
		return "ESCAPED"
	end try
	`, dialogText, buttons)
}

func (m *MacOSManager) DeleteServiceAccountToken(ctx context.Context) error {
	log.Println("[SECURITY] Shredding the vault token from the Keychain...")
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "security", "delete-generic-password", "-l", "GoLAPS_Vault_Token", "/Library/Keychains/System.keychain")
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	// Nothing to shred is the expected outcome of a manual run that took the token from the
	// environment instead of the keychain — not worth alarming an operator over.
	if strings.Contains(string(out), "could not be found") {
		log.Println("[INFO] No token was present in the Keychain; nothing to shred.")
		return nil
	}
	return fmt.Errorf("could not delete the keychain token: %w | output: %s", err, strings.TrimSpace(string(out)))
}
