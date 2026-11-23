// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

package core

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"golaps/internal/config"
	"golaps/internal/osmgmt"
	"golaps/internal/vault"
	"golaps/internal/version"
)

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
	rec *recorder
	seenCandidates []string
	sysInfoErr  error
	rotateErr   error
	tokenStatus string
	rotatedPass string
	cleanupAbsent bool
	escrow        osmgmt.BridgeEscrow
	seenCreds map[string]string
	verifyLive   map[string]bool
	verifyErr    error
	seenVerified []string
}

func (f *fakeManager) VerifyPassword(ctx context.Context, user, pass string) (bool, error) {
	f.rec.record("VerifyPassword")
	f.seenVerified = append(f.seenVerified, pass)
	if f.verifyErr != nil {
		return false, f.verifyErr
	}
	return f.verifyLive[pass], nil
}

func (f *fakeManager) GetSystemInfo(ctx context.Context) (string, string, error) {
	f.rec.record("GetSystemInfo")
	if f.sysInfoErr != nil {
		return "MAC-001", "", f.sysInfoErr
	}
	return "MAC-001", "SERIAL123", nil
}

func (f *fakeManager) EnsureUserAndChangePassword(ctx context.Context, user string, candidates []string, newPass string) error {
	f.seenCandidates = candidates
	f.rec.record("EnsureUserAndChangePassword")
	f.rotatedPass = newPass
	return f.rotateErr
}

func (f *fakeManager) ManageSecureToken(ctx context.Context, targetUser, newPass string, availableCreds map[string]string) string {
	f.rec.record("ManageSecureToken")
	f.seenCreds = availableCreds
	if f.tokenStatus == "" {
		return "ENABLED (Silent - Vault)"
	}
	return f.tokenStatus
}

func (f *fakeManager) DeleteServiceAccountToken(ctx context.Context) error { return nil }

func (f *fakeManager) Preflight(ctx context.Context, user, probeURL string) error {
	f.rec.record("Preflight")
	return nil
}

func (f *fakeManager) CleanupLegacyAdmin(ctx context.Context, targetUser string) bool {
	f.rec.record("CleanupLegacyAdmin")
	return f.cleanupAbsent
}

func (f *fakeManager) SetBridgeEscrow(escrow osmgmt.BridgeEscrow) {
	f.rec.record("SetBridgeEscrow")
	f.escrow = escrow
}

type fakeVault struct {
	rec        *recorder
	creds      *vault.Credentials
	getErr     error
	stageErr   error
	upsertErr  error
	stagedPass string
	savedPass  string
	savedToken string
	bridgePass string
	bridgeErr  error
	confirmedLive string
	confirmErr    error
}

func (f *fakeVault) ConfirmLivePassword(ctx context.Context, creds *vault.Credentials, deviceID, hostname, vaultID, login, live string) error {
	f.rec.record("ConfirmLivePassword")
	f.confirmedLive = live
	if f.confirmErr != nil {
		return f.confirmErr
	}
	creds.OldPassword = live
	creds.PendingPassword = ""
	creds.PreviousPendingPassword = ""
	return nil
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

func (f *fakeVault) StageBridgePassword(ctx context.Context, creds *vault.Credentials, vaultID, password string) error {
	f.rec.record("StageBridgePassword")
	f.bridgePass = password
	creds.BridgePassword = password
	return f.bridgeErr
}

func (f *fakeVault) ClearBridgePassword(ctx context.Context, creds *vault.Credentials, vaultID string) error {
	f.rec.record("ClearBridgePassword")
	creds.BridgePassword = ""
	return nil
}

func testConfig() *config.Config {
	return &config.Config{AdminUser: "localadmin", VaultID: "vault1", PassLength: 18}
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
	v := &fakeVault{rec: rec, getErr: errors.New("1Password unreachable")}

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
	mgr := &fakeManager{rec: rec, rotateErr: errors.New("localadminminctl refused")}
	v := &fakeVault{rec: rec}

	err := RunLAPS(context.Background(), testConfig(), mgr, v)
	if err == nil {
		t.Fatal("RunLAPS should fail when the OS rotation fails")
	}
	if rec.indexOf("UpsertCredentials") != -1 {
		t.Errorf("the vault was told the rotation succeeded when it did not: %v", rec.calls)
	}
}

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

func TestRunLAPSRetiresLegacyAdminOnlyAfterVaultWrite(t *testing.T) {
	rec := &recorder{}
	mgr := &fakeManager{rec: rec, tokenStatus: "DISABLED (Review Required)"}
	v := &fakeVault{rec: rec}

	_ = RunLAPS(context.Background(), testConfig(), mgr, v)

	cleanup, upsert := rec.indexOf("CleanupLegacyAdmin"), rec.indexOf("UpsertCredentials")
	if cleanup == -1 || upsert == -1 || cleanup < upsert {
		t.Fatalf("cleanup must follow the vault write: %v", rec.calls)
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
	if rec.indexOf("CleanupLegacyAdmin") != -1 {
		t.Errorf("laps-bridge must not be touched when the vault write failed: %v", rec.calls)
	}
}

func TestRunLAPSPrefersStagedPasswordWhenNoneRecorded(t *testing.T) {
	rec := &recorder{}
	mgr := &fakeManager{rec: rec, verifyErr: errors.ErrUnsupported}
	v := &fakeVault{rec: rec, creds: &vault.Credentials{PendingPassword: "staged-from-last-run"}}

	cfg := testConfig()
	cfg.LegacyAdminPass = "mdm-fallback"

	if err := RunLAPS(context.Background(), cfg, mgr, v); err != nil {
		t.Fatalf("RunLAPS returned an error: %v", err)
	}

	if !reflect.DeepEqual(mgr.seenCandidates, []string{"staged-from-last-run", "mdm-fallback"}) {
		t.Errorf("candidates = %q, want the staged one first and the MDM fallback last", mgr.seenCandidates)
	}
}

func TestRotationCandidatesOrderAndDedup(t *testing.T) {
	creds := &vault.Credentials{PendingPassword: "P2", PreviousPendingPassword: "P1", OldPassword: "OLD"}
	if got := rotationCandidates(creds, "legacy"); !reflect.DeepEqual(got, []string{"P2", "P1", "OLD", "legacy"}) {
		t.Fatalf("candidates = %q, want [P2 P1 OLD legacy]", got)
	}
	creds = &vault.Credentials{PendingPassword: "P2", OldPassword: "P2"}
	if got := rotationCandidates(creds, ""); !reflect.DeepEqual(got, []string{"P2"}) {
		t.Fatalf("candidates = %q, want [P2]", got)
	}
	if got := rotationCandidates(&vault.Credentials{}, ""); len(got) != 0 {
		t.Fatalf("candidates = %q, want none", got)
	}
}

func TestRunLAPSLegacyPasswordIsTheLastCandidate(t *testing.T) {
	rec := &recorder{}
	mgr := &fakeManager{rec: rec}
	v := &fakeVault{rec: rec, creds: &vault.Credentials{OldPassword: "previous-owner"}}
	cfg := testConfig()
	cfg.LegacyAdminPass = "enrollment"

	if err := RunLAPS(context.Background(), cfg, mgr, v); err != nil {
		t.Fatalf("RunLAPS returned an error: %v", err)
	}
	if !reflect.DeepEqual(mgr.seenCandidates, []string{"previous-owner", "enrollment"}) {
		t.Fatalf("candidates = %q, want the recorded password and then the enrollment password", mgr.seenCandidates)
	}
}

func TestRunLAPSAbortsBeforeVaultAccessWithoutSerial(t *testing.T) {
	rec := &recorder{}
	mgr := &fakeManager{rec: rec, sysInfoErr: errors.New("ioreg reported no IOPlatformSerialNumber")}
	v := &fakeVault{rec: rec}

	err := RunLAPS(context.Background(), testConfig(), mgr, v)
	if err == nil {
		t.Fatal("RunLAPS must fail when the device has no serial")
	}
	if !strings.Contains(err.Error(), "serial") {
		t.Fatalf("the error must name the missing serial, got: %v", err)
	}
	for _, step := range []string{"GetCredentials", "StagePendingPassword", "UpsertCredentials", "ClearPendingPassword", "EnsureUserAndChangePassword"} {
		if rec.indexOf(step) != -1 {
			t.Fatalf("%s ran although the device has no serial: %v", step, rec.calls)
		}
	}
}

func TestRunLAPSSucceedsWithWarningWhenRecoveryCovered(t *testing.T) {
	rec := &recorder{}
	mgr := &fakeManager{rec: rec, tokenStatus: osmgmt.TokenStatusDisabledCovered}
	v := &fakeVault{rec: rec}

	if err := RunLAPS(context.Background(), testConfig(), mgr, v); err != nil {
		t.Fatalf("a tokenless admin on an MDM-covered device must not fail the run: %v", err)
	}
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
	if rec.indexOf("ClearPendingPassword") != -1 {
		t.Fatalf("the pending password was cleared on a non-policy failure: %v", rec.calls)
	}
}

func TestRunLAPSStartsWithPendingWhenPresent(t *testing.T) {
	rec := &recorder{}
	mgr := &fakeManager{rec: rec, verifyErr: errors.ErrUnsupported}
	v := &fakeVault{rec: rec, creds: &vault.Credentials{OldPassword: "recorded", PendingPassword: "staged"}}
	if err := RunLAPS(context.Background(), testConfig(), mgr, v); err != nil {
		t.Fatalf("RunLAPS failed: %v", err)
	}
	if !reflect.DeepEqual(mgr.seenCandidates, []string{"staged", "recorded"}) {
		t.Fatalf("candidates = %q, want [staged recorded]", mgr.seenCandidates)
	}

	rec2 := &recorder{}
	mgr2 := &fakeManager{rec: rec2}
	v2 := &fakeVault{rec: rec2, creds: &vault.Credentials{OldPassword: "recorded"}}
	if err := RunLAPS(context.Background(), testConfig(), mgr2, v2); err != nil {
		t.Fatalf("RunLAPS failed: %v", err)
	}
	if !reflect.DeepEqual(mgr2.seenCandidates, []string{"recorded"}) {
		t.Fatalf("candidates = %q, want [recorded]", mgr2.seenCandidates)
	}
}

func TestRunLAPSWiresBridgePasswordAndEscrow(t *testing.T) {
	rec := &recorder{}
	mgr := &fakeManager{rec: rec, cleanupAbsent: true}
	v := &fakeVault{rec: rec, creds: &vault.Credentials{ItemID: "item1", OldPassword: "old", BridgePassword: "bridge-pw"}}

	if err := RunLAPS(context.Background(), testConfig(), mgr, v); err != nil {
		t.Fatalf("RunLAPS returned an error: %v", err)
	}
	if mgr.seenCreds[osmgmt.LegacyBridgeAdmin] != "bridge-pw" {
		t.Fatalf("the escrowed bridge password must reach the candidate loop as the laps-bridge credential: %v", mgr.seenCreds)
	}
	if mgr.escrow == nil {
		t.Fatal("the escrow route was not wired")
	}
	if err := mgr.escrow(context.Background(), "new-bridge-pw"); err != nil || v.bridgePass != "new-bridge-pw" {
		t.Fatalf("the escrow route must write through the vault client (err=%v, stored=%q)", err, v.bridgePass)
	}
	wire, rotate := rec.indexOf("SetBridgeEscrow"), rec.indexOf("EnsureUserAndChangePassword")
	if wire == -1 || wire > rotate {
		t.Fatalf("the escrow route must exist before the rotation: %v", rec.calls)
	}
	cleanup, clear := rec.indexOf("CleanupLegacyAdmin"), rec.indexOf("ClearBridgePassword")
	if clear == -1 || clear < cleanup {
		t.Fatalf("the bridge field must be cleared after the cleanup removed laps-bridge: %v", rec.calls)
	}
}

func TestRunLAPSKeepsBridgePasswordWhileBridgeExists(t *testing.T) {
	rec := &recorder{}
	mgr := &fakeManager{rec: rec, cleanupAbsent: false}
	v := &fakeVault{rec: rec, creds: &vault.Credentials{ItemID: "item1", OldPassword: "old", BridgePassword: "bridge-pw"}}

	if err := RunLAPS(context.Background(), testConfig(), mgr, v); err != nil {
		t.Fatalf("RunLAPS returned an error: %v", err)
	}
	if rec.indexOf("ClearBridgePassword") != -1 {
		t.Fatalf("the bridge password must stay while the bridge exists: %v", rec.calls)
	}
}

func TestRunLAPSBridgeFieldWinsOverLegacyBridgePassword(t *testing.T) {
	rec := &recorder{}
	mgr := &fakeManager{rec: rec}
	v := &fakeVault{rec: rec, creds: &vault.Credentials{ItemID: "item1", OldPassword: "old", LegacyLogin: "laps-bridge", LegacyPassword: "legacy", BridgePassword: "bridge-pw"}}

	if err := RunLAPS(context.Background(), testConfig(), mgr, v); err != nil {
		t.Fatalf("RunLAPS returned an error: %v", err)
	}
	if mgr.seenCreds["laps-bridge"] != "bridge-pw" {
		t.Fatalf("the escrowed bridge password must win over the stale legacy field: %v", mgr.seenCreds)
	}
}

func TestRunLAPSLegacyBridgePasswordWithoutBridgeField(t *testing.T) {
	rec := &recorder{}
	mgr := &fakeManager{rec: rec}
	v := &fakeVault{rec: rec, creds: &vault.Credentials{ItemID: "item1", OldPassword: "old", LegacyLogin: "laps-bridge", LegacyPassword: "legacy"}}

	if err := RunLAPS(context.Background(), testConfig(), mgr, v); err != nil {
		t.Fatalf("RunLAPS returned an error: %v", err)
	}
	if mgr.seenCreds["laps-bridge"] != "legacy" {
		t.Fatalf("the legacy password must be the laps-bridge credential when no bridge field exists: %v", mgr.seenCreds)
	}
}

func TestRunLAPSDisabledNotCoveredStaysRed(t *testing.T) {
	cases := []struct {
		name   string
		status string
	}{
		{"laps-bridge deadlock", osmgmt.TokenStatusDisabledDeadlock},
		{"wrong password streak", osmgmt.TokenStatusDisabledWrongPassword},
		{"window ended early", osmgmt.TokenStatusDisabledWindowKilled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recorder{}
			mgr := &fakeManager{rec: rec, tokenStatus: tc.status}
			v := &fakeVault{rec: rec}

			err := RunLAPS(context.Background(), testConfig(), mgr, v)
			if err == nil {
				t.Fatalf("%s must fail the run", tc.name)
			}
			if v.savedToken != tc.status {
				t.Fatalf("the vault must still record the state: %q", v.savedToken)
			}
		})
	}
}

func TestVaultIntegrationVersionIsTheLAPSVersion(t *testing.T) {
	if got := vault.IntegrationVersion(); got != "v"+version.Version {
		t.Fatalf("vault integration version = %q, want v%s", got, version.Version)
	}
}

func TestRunLAPSConfirmsLivePendingBeforeStaging(t *testing.T) {
	rec := &recorder{}
	mgr := &fakeManager{rec: rec, verifyLive: map[string]bool{"P1": true}}
	v := &fakeVault{rec: rec, creds: &vault.Credentials{ItemID: "item1", OldPassword: "recorded", PendingPassword: "P2", PreviousPendingPassword: "P1"}}
	cfg := testConfig()
	cfg.LegacyAdminPass = "enrollment"

	if err := RunLAPS(context.Background(), cfg, mgr, v); err != nil {
		t.Fatalf("RunLAPS returned an error: %v", err)
	}
	if !reflect.DeepEqual(mgr.seenVerified, []string{"P2", "P1"}) {
		t.Fatalf("verified %q, want the walk to stop at the first live candidate [P2 P1]", mgr.seenVerified)
	}
	if v.confirmedLive != "P1" {
		t.Fatalf("ConfirmLivePassword received %q, want the live value P1", v.confirmedLive)
	}
	confirm, stage := rec.indexOf("ConfirmLivePassword"), rec.indexOf("StagePendingPassword")
	if confirm == -1 || stage == -1 || confirm > stage {
		t.Fatalf("the live value must be confirmed before the new one is staged: %v", rec.calls)
	}
	if verify := rec.indexOf("VerifyPassword"); verify == -1 || verify > stage {
		t.Fatalf("the verification must run before the staging: %v", rec.calls)
	}
	if !reflect.DeepEqual(mgr.seenCandidates, []string{"P1"}) {
		t.Fatalf("candidates = %q, want only the verified live value", mgr.seenCandidates)
	}
	if v.creds.OldPassword != "P1" || v.creds.PendingPassword != "" || v.creds.PreviousPendingPassword != "" {
		t.Fatalf("creds after the confirm = %+v, want the live value recorded and both pending values cleared", *v.creds)
	}
}

func TestRunLAPSRecordedLiveNeedsNoConfirmWrite(t *testing.T) {
	rec := &recorder{}
	mgr := &fakeManager{rec: rec, verifyLive: map[string]bool{"recorded": true}}
	v := &fakeVault{rec: rec, creds: &vault.Credentials{ItemID: "item1", OldPassword: "recorded", PendingPassword: "P1"}}
	cfg := testConfig()
	cfg.LegacyAdminPass = "enrollment"

	if err := RunLAPS(context.Background(), cfg, mgr, v); err != nil {
		t.Fatalf("RunLAPS returned an error: %v", err)
	}
	if rec.indexOf("ConfirmLivePassword") != -1 {
		t.Fatalf("the recorded password is live, so no confirm write is needed: %v", rec.calls)
	}
	if !reflect.DeepEqual(mgr.seenVerified, []string{"P1", "recorded"}) {
		t.Fatalf("verified %q, want [P1 recorded]", mgr.seenVerified)
	}
	if !reflect.DeepEqual(mgr.seenCandidates, []string{"recorded"}) {
		t.Fatalf("candidates = %q, want [recorded]", mgr.seenCandidates)
	}
}

func TestRunLAPSNoLiveVaultCopyLeavesTheRestToTheRotation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		legacy string
		want   []string
	}{
		{name: "legacy configured", legacy: "enrollment", want: []string{"enrollment"}},
		{name: "no legacy", legacy: "", want: []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recorder{}
			mgr := &fakeManager{rec: rec, verifyLive: map[string]bool{}}
			v := &fakeVault{rec: rec, creds: &vault.Credentials{ItemID: "item1", OldPassword: "recorded", PendingPassword: "P2", PreviousPendingPassword: "P1"}}
			cfg := testConfig()
			cfg.LegacyAdminPass = tc.legacy

			if err := RunLAPS(context.Background(), cfg, mgr, v); err != nil {
				t.Fatalf("RunLAPS returned an error: %v", err)
			}
			if !reflect.DeepEqual(mgr.seenVerified, []string{"P2", "P1", "recorded"}) {
				t.Fatalf("verified %q, want the three vault copies once and never the legacy password", mgr.seenVerified)
			}
			if rec.indexOf("EnsureUserAndChangePassword") == -1 {
				t.Fatalf("the rotation step must still run: %v", rec.calls)
			}
			if !reflect.DeepEqual(mgr.seenCandidates, tc.want) {
				t.Fatalf("candidates = %q, want %q", mgr.seenCandidates, tc.want)
			}
			if rec.indexOf("ConfirmLivePassword") != -1 {
				t.Fatalf("nothing is live, so nothing must be confirmed: %v", rec.calls)
			}
		})
	}
}

func TestRunLAPSVerificationErrorKeepsFullCandidateList(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{name: "unsupported", err: errors.ErrUnsupported},
		{name: "helper could not run", err: errors.New("fork/exec: no such file")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recorder{}
			mgr := &fakeManager{rec: rec, verifyErr: tc.err}
			v := &fakeVault{rec: rec, creds: &vault.Credentials{ItemID: "item1", OldPassword: "recorded", PendingPassword: "P1"}}
			cfg := testConfig()
			cfg.LegacyAdminPass = "enrollment"

			if err := RunLAPS(context.Background(), cfg, mgr, v); err != nil {
				t.Fatalf("RunLAPS returned an error: %v", err)
			}
			if !reflect.DeepEqual(mgr.seenCandidates, []string{"P1", "recorded", "enrollment"}) {
				t.Fatalf("candidates = %q, want the full list [P1 recorded enrollment]", mgr.seenCandidates)
			}
			if rec.indexOf("ConfirmLivePassword") != -1 {
				t.Fatalf("no confirm write without a verification: %v", rec.calls)
			}
		})
	}
}

func TestRunLAPSSkipsVerificationWithoutPending(t *testing.T) {
	rec := &recorder{}
	mgr := &fakeManager{rec: rec, verifyLive: map[string]bool{"recorded": true}}
	v := &fakeVault{rec: rec, creds: &vault.Credentials{ItemID: "item1", OldPassword: "recorded"}}

	if err := RunLAPS(context.Background(), testConfig(), mgr, v); err != nil {
		t.Fatalf("RunLAPS returned an error: %v", err)
	}
	if rec.indexOf("VerifyPassword") != -1 {
		t.Fatalf("no pending value, so no verification: %v", rec.calls)
	}
	if !reflect.DeepEqual(mgr.seenCandidates, []string{"recorded"}) {
		t.Fatalf("candidates = %q, want [recorded]", mgr.seenCandidates)
	}
}

func TestRunLAPSAbortsWhenConfirmWriteFails(t *testing.T) {
	rec := &recorder{}
	mgr := &fakeManager{rec: rec, verifyLive: map[string]bool{"P1": true}}
	v := &fakeVault{rec: rec, confirmErr: errors.New("put failed"), creds: &vault.Credentials{ItemID: "item1", OldPassword: "recorded", PendingPassword: "P1"}}

	if err := RunLAPS(context.Background(), testConfig(), mgr, v); err == nil {
		t.Fatal("RunLAPS must fail when the live password cannot be recorded")
	}
	for _, step := range []string{"StagePendingPassword", "EnsureUserAndChangePassword"} {
		if rec.indexOf(step) != -1 {
			t.Fatalf("%s ran although the vault refused the confirm write: %v", step, rec.calls)
		}
	}
}
