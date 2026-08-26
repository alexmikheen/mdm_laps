package core

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"golaps/internal/config"
	"golaps/internal/osmgmt"
	"golaps/internal/vault"
)

// recorder captures the order in which the orchestrator touched the device and the vault. The ordering is the point: escrow must happen before the irreversible rotation.
type recorder struct {
	calls []string
}

func (r *recorder) record(step string) { r.calls = append(r.calls, step) }

func (r *recorder) indexOf(step string) int {
	for i, c := range r.calls {
		if c == step {
			return i
		}
	}
	return -1
}

type fakeManager struct {
	rec         *recorder
	seenAlt     string
	seenOld     string
	rotateErr   error
	tokenStatus string
	rotatedPass string
}

func (f *fakeManager) GetSystemInfo(ctx context.Context) (string, string) {
	f.rec.record("GetSystemInfo")
	return "MAC-001", "SERIAL123"
}

func (f *fakeManager) EnsureUserAndChangePassword(ctx context.Context, user, oldPass, altOldPass, newPass string) error {
	f.seenAlt = altOldPass
	f.seenOld = oldPass
	f.rec.record("EnsureUserAndChangePassword")
	f.rotatedPass = newPass
	return f.rotateErr
}

func (f *fakeManager) ManageSecureToken(ctx context.Context, targetUser, newPass string, availableCreds map[string]string) string {
	f.rec.record("ManageSecureToken")
	if f.tokenStatus == "" {
		return "ENABLED (Silent - Vault)"
	}
	return f.tokenStatus
}

func (f *fakeManager) DeleteServiceAccountToken(ctx context.Context) error { return nil }

type fakeVault struct {
	rec        *recorder
	creds      *vault.Credentials
	getErr     error
	stageErr   error
	upsertErr  error
	stagedPass string
	savedPass  string
	savedToken string
}

func (f *fakeVault) GetCredentials(ctx context.Context, deviceID, vaultID, targetAdmin string) (*vault.Credentials, error) {
	f.rec.record("GetCredentials")
	if f.creds == nil {
		f.creds = &vault.Credentials{}
	}
	return f.creds, f.getErr
}

func (f *fakeVault) StagePendingPassword(ctx context.Context, creds *vault.Credentials, deviceID, hostname, vaultID, newLogin, newPassword string) error {
	f.rec.record("StagePendingPassword")
	f.stagedPass = newPassword
	return f.stageErr
}

func (f *fakeVault) UpsertCredentials(ctx context.Context, creds *vault.Credentials, deviceID, hostname, vaultID, newLogin, newPassword, tokenStatus string) error {
	f.rec.record("UpsertCredentials")
	f.savedPass = newPassword
	f.savedToken = tokenStatus
	return f.upsertErr
}

func (f *fakeVault) ClearPendingPassword(ctx context.Context, creds *vault.Credentials, vaultID string) error {
	f.rec.record("ClearPendingPassword")
	return nil
}

func testConfig() *config.Config {
	return &config.Config{AdminUser: "lapsadmin", VaultID: "vault1", PassLength: 18}
}

func TestRunLAPSHappyPath(t *testing.T) {
	rec := &recorder{}
	mgr := &fakeManager{rec: rec}
	v := &fakeVault{rec: rec}

	if err := RunLAPS(context.Background(), testConfig(), mgr, v); err != nil {
		t.Fatalf("RunLAPS returned an error: %v", err)
	}

	if v.savedPass != mgr.rotatedPass {
		t.Errorf("escrowed password %q differs from the one applied to the device %q", v.savedPass, mgr.rotatedPass)
	}
	if v.stagedPass != mgr.rotatedPass {
		t.Errorf("staged password %q differs from the one applied to the device %q", v.stagedPass, mgr.rotatedPass)
	}
}

// The rotation is irreversible and the vault holds the only copy of the result, so the escrow must be written first. Reversing these two is what leaves a device with a password nobody has.
func TestRunLAPSEscrowsBeforeRotating(t *testing.T) {
	rec := &recorder{}
	mgr := &fakeManager{rec: rec}
	v := &fakeVault{rec: rec}

	if err := RunLAPS(context.Background(), testConfig(), mgr, v); err != nil {
		t.Fatalf("RunLAPS returned an error: %v", err)
	}

	stage := rec.indexOf("StagePendingPassword")
	rotate := rec.indexOf("EnsureUserAndChangePassword")
	if stage == -1 || rotate == -1 {
		t.Fatalf("expected both a staging and a rotation call, got %v", rec.calls)
	}
	if stage > rotate {
		t.Errorf("password was rotated before it was escrowed: %v", rec.calls)
	}
}

func TestRunLAPSAbortsWhenVaultCannotBeRead(t *testing.T) {
	rec := &recorder{}
	mgr := &fakeManager{rec: rec}
	v := &fakeVault{rec: rec, getErr: errors.New("vault unreachable")}

	err := RunLAPS(context.Background(), testConfig(), mgr, v)
	if err == nil {
		t.Fatal("RunLAPS should fail when the vault cannot be read")
	}
	if rec.indexOf("EnsureUserAndChangePassword") != -1 {
		t.Errorf("the device was rotated despite an unreadable vault: %v", rec.calls)
	}
}

func TestRunLAPSAbortsWhenEscrowFails(t *testing.T) {
	rec := &recorder{}
	mgr := &fakeManager{rec: rec}
	v := &fakeVault{rec: rec, stageErr: errors.New("write denied")}

	err := RunLAPS(context.Background(), testConfig(), mgr, v)
	if err == nil {
		t.Fatal("RunLAPS should fail when the new password cannot be escrowed")
	}
	if rec.indexOf("EnsureUserAndChangePassword") != -1 {
		t.Errorf("the device was rotated even though the escrow failed: %v", rec.calls)
	}
}

func TestRunLAPSDoesNotSyncVaultWhenRotationFails(t *testing.T) {
	rec := &recorder{}
	mgr := &fakeManager{rec: rec, rotateErr: errors.New("sysadminctl refused")}
	v := &fakeVault{rec: rec}

	err := RunLAPS(context.Background(), testConfig(), mgr, v)
	if err == nil {
		t.Fatal("RunLAPS should fail when the OS rotation fails")
	}
	if rec.indexOf("UpsertCredentials") != -1 {
		t.Errorf("the vault was told the rotation succeeded when it did not: %v", rec.calls)
	}
}

// Without a Secure Token the account cannot unlock FileVault. The password must still be escrowed (otherwise the device is unreachable), but the run has to end non-zero — reporting success here is what made the MDM show "Pass" for devices left with no recovery account.
func TestRunLAPSFailsButStillEscrowsWhenTokenGrantFails(t *testing.T) {
	rec := &recorder{}
	mgr := &fakeManager{rec: rec, tokenStatus: "DISABLED (Review Required)"}
	v := &fakeVault{rec: rec}

	err := RunLAPS(context.Background(), testConfig(), mgr, v)
	if err == nil {
		t.Fatal("RunLAPS should fail when the target admin ends with no Secure Token")
	}
	if !strings.Contains(err.Error(), "FileVault") {
		t.Errorf("error should explain the FileVault consequence, got: %v", err)
	}

	upsert := rec.indexOf("UpsertCredentials")
	if upsert == -1 {
		t.Fatalf("the rotated password was not escrowed: %v", rec.calls)
	}
	if v.savedPass != mgr.rotatedPass {
		t.Errorf("escrowed password %q differs from the one applied to the device %q", v.savedPass, mgr.rotatedPass)
	}
	if v.savedToken != "DISABLED (Review Required)" {
		t.Errorf("token status recorded as %q, want the DISABLED status", v.savedToken)
	}
}

func TestRunLAPSReportsVaultWriteFailure(t *testing.T) {
	rec := &recorder{}
	mgr := &fakeManager{rec: rec}
	v := &fakeVault{rec: rec, upsertErr: errors.New("put failed")}

	err := RunLAPS(context.Background(), testConfig(), mgr, v)
	if err == nil {
		t.Fatal("RunLAPS should fail when the vault write fails")
	}
}

// A password staged by a run that died mid-rotation may already be the live one, so it is a better reset candidate than the MDM fallback when nothing else is recorded.
func TestRunLAPSPrefersStagedPasswordWhenNoneRecorded(t *testing.T) {
	rec := &recorder{}
	var seenOldPass string
	mgr := &fakeManager{rec: rec}
	v := &fakeVault{rec: rec, creds: &vault.Credentials{PendingPassword: "staged-from-last-run"}}

	cfg := testConfig()
	cfg.LegacyAdminPass = "mdm-fallback"

	wrapped := &oldPassSpy{fakeManager: mgr, seen: &seenOldPass}
	if err := RunLAPS(context.Background(), cfg, wrapped, v); err != nil {
		t.Fatalf("RunLAPS returned an error: %v", err)
	}

	if seenOldPass != "staged-from-last-run" {
		t.Errorf("reset used %q as the old password, want the staged one", seenOldPass)
	}
}

type oldPassSpy struct {
	*fakeManager
	seen *string
}

func (o *oldPassSpy) EnsureUserAndChangePassword(ctx context.Context, user, oldPass, altOldPass, newPass string) error {
	*o.seen = oldPass
	return o.fakeManager.EnsureUserAndChangePassword(ctx, user, oldPass, altOldPass, newPass)
}

func TestRunLAPSSucceedsWithWarningWhenRecoveryCovered(t *testing.T) {
	rec := &recorder{}
	mgr := &fakeManager{rec: rec, tokenStatus: osmgmt.TokenStatusDisabledCovered}
	v := &fakeVault{rec: rec}

	if err := RunLAPS(context.Background(), testConfig(), mgr, v); err != nil {
		t.Fatalf("a tokenless admin on an MDM-covered device must not fail the run: %v", err)
	}
	// The degraded state still has to be visible in the vault record.
	if v.savedToken != osmgmt.TokenStatusDisabledCovered {
		t.Errorf("token status recorded as %q, want %q", v.savedToken, osmgmt.TokenStatusDisabledCovered)
	}
}

func TestRunLAPSClearsPendingOnPolicyRejectedRotation(t *testing.T) {
	rec := &recorder{}
	mgr := &fakeManager{rec: rec, rotateErr: fmt.Errorf("rotation refused: %w", osmgmt.ErrPolicyRejected)}
	v := &fakeVault{rec: rec}

	err := RunLAPS(context.Background(), testConfig(), mgr, v)
	if err == nil {
		t.Fatal("a policy-rejected rotation must still fail the run")
	}
	// The refused password never reached the device, so the staged copy must not survive to poison the next run's passForReset fallback.
	if rec.indexOf("ClearPendingPassword") == -1 {
		t.Fatalf("the refused pending password was not cleared: %v", rec.calls)
	}
	if rec.indexOf("UpsertCredentials") != -1 {
		t.Fatalf("UpsertCredentials must not run after a failed rotation: %v", rec.calls)
	}
}

func TestRunLAPSKeepsPendingOnOtherRotationFailures(t *testing.T) {
	rec := &recorder{}
	mgr := &fakeManager{rec: rec, rotateErr: errors.New("opendirectoryd timeout")}
	v := &fakeVault{rec: rec}

	if err := RunLAPS(context.Background(), testConfig(), mgr, v); err == nil {
		t.Fatal("a failed rotation must fail the run")
	}
	// For any other failure the staged password may BE the one the device took mid-rotation — it must stay as the recovery candidate.
	if rec.indexOf("ClearPendingPassword") != -1 {
		t.Fatalf("the pending password was cleared on a non-policy failure: %v", rec.calls)
	}
}

func TestRunLAPSStartsWithPendingWhenPresent(t *testing.T) {
	// A surviving pending copy is the likeliest live password (the previous run died after rotating), so it goes FIRST and the recorded one becomes the fallback.
	rec := &recorder{}
	mgr := &fakeManager{rec: rec}
	v := &fakeVault{rec: rec, creds: &vault.Credentials{OldPassword: "recorded", PendingPassword: "staged"}}
	if err := RunLAPS(context.Background(), testConfig(), mgr, v); err != nil {
		t.Fatalf("RunLAPS failed: %v", err)
	}
	if mgr.seenOld != "staged" || mgr.seenAlt != "recorded" {
		t.Fatalf("candidate order = (%q, %q), want (staged, recorded)", mgr.seenOld, mgr.seenAlt)
	}

	// No pending copy: the recorded password stays the primary and there is no alternate.
	rec2 := &recorder{}
	mgr2 := &fakeManager{rec: rec2}
	v2 := &fakeVault{rec: rec2, creds: &vault.Credentials{OldPassword: "recorded"}}
	if err := RunLAPS(context.Background(), testConfig(), mgr2, v2); err != nil {
		t.Fatalf("RunLAPS failed: %v", err)
	}
	if mgr2.seenOld != "recorded" || mgr2.seenAlt != "" {
		t.Fatalf("candidate order = (%q, %q), want (recorded, none)", mgr2.seenOld, mgr2.seenAlt)
	}
}
