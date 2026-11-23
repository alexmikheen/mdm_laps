// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

package vault

import (
	"context"
	"fmt"
	"testing"
)

type fakeBWStore struct {
	nextID  int
	secrets map[string]*bwSecret
}

func newFakeBWStore() *fakeBWStore {
	return &fakeBWStore{secrets: map[string]*bwSecret{}}
}

func (f *fakeBWStore) List(orgID string) ([]bwSecret, error) {
	var out []bwSecret
	for _, s := range f.secrets {
		out = append(out, *s)
	}
	return out, nil
}

func (f *fakeBWStore) Get(secretID string) (*bwSecret, error) {
	s, ok := f.secrets[secretID]
	if !ok {
		return nil, fmt.Errorf("secret %s not found", secretID)
	}
	cp := *s
	return &cp, nil
}

func (f *fakeBWStore) Create(key, value, note, orgID string, projectIDs []string) (*bwSecret, error) {
	f.nextID++
	id := fmt.Sprintf("bw-sec-%d", f.nextID)
	s := &bwSecret{ID: id, Key: key, Value: value, Note: note}
	f.secrets[id] = s
	cp := *s
	return &cp, nil
}

func (f *fakeBWStore) Update(secretID, key, value, note, orgID string, projectIDs []string) (*bwSecret, error) {
	if _, ok := f.secrets[secretID]; !ok {
		return nil, fmt.Errorf("secret %s not found", secretID)
	}
	s := &bwSecret{ID: secretID, Key: key, Value: value, Note: note}
	f.secrets[secretID] = s
	cp := *s
	return &cp, nil
}

func (f *fakeBWStore) Close() {}

func TestBitwardenClientFullLifecycle(t *testing.T) {
	store := newFakeBWStore()
	client := newBWClientWithStore(store, "org-uuid-1")
	ctx := context.Background()
	deviceID := "C02BWTEST01"
	hostname := "bw-macbook"
	projectID := "proj-uuid-1"
	admin := "localadmin"

	creds, err := client.GetCredentials(ctx, deviceID, projectID, admin)
	if err != nil {
		t.Fatalf("initial GetCredentials: %v", err)
	}
	if creds.OldPassword != "" {
		t.Fatalf("expected empty password, got %q", creds.OldPassword)
	}

	if err := client.StagePendingPassword(ctx, creds, deviceID, hostname, projectID, admin, "Pending#1"); err != nil {
		t.Fatalf("StagePendingPassword #1: %v", err)
	}
	if creds.ItemID == "" {
		t.Fatal("expected ItemID to be set after staging")
	}

	read1, err := client.GetCredentials(ctx, deviceID, projectID, admin)
	if err != nil || read1.PendingPassword != "Pending#1" {
		t.Fatalf("read1 = (%+v, %v), want Pending#1", read1, err)
	}

	if err := client.StagePendingPassword(ctx, read1, deviceID, hostname, projectID, admin, "Pending#2"); err != nil {
		t.Fatalf("StagePendingPassword #2: %v", err)
	}
	read2, err := client.GetCredentials(ctx, deviceID, projectID, admin)
	if err != nil || read2.PendingPassword != "Pending#2" || read2.PreviousPendingPassword != "Pending#1" {
		t.Fatalf("read2 = (%+v, %v)", read2, err)
	}

	if err := client.ClearPendingPassword(ctx, read2, projectID); err != nil {
		t.Fatalf("ClearPendingPassword: %v", err)
	}
	read3, err := client.GetCredentials(ctx, deviceID, projectID, admin)
	if err != nil || read3.PendingPassword != "Pending#1" || read3.PreviousPendingPassword != "" {
		t.Fatalf("read3 = (%+v, %v)", read3, err)
	}

	if err := client.ConfirmLivePassword(ctx, read3, deviceID, hostname, projectID, admin, "Pending#1"); err != nil {
		t.Fatalf("ConfirmLivePassword: %v", err)
	}
	read4, err := client.GetCredentials(ctx, deviceID, projectID, admin)
	if err != nil || read4.OldPassword != "Pending#1" || read4.PendingPassword != "" {
		t.Fatalf("read4 = (%+v, %v)", read4, err)
	}

	if err := client.StageBridgePassword(ctx, read4, projectID, "Bridge#1"); err != nil {
		t.Fatalf("StageBridgePassword: %v", err)
	}
	read5, err := client.GetCredentials(ctx, deviceID, projectID, admin)
	if err != nil || read5.BridgePassword != "Bridge#1" {
		t.Fatalf("read5 = (%+v, %v)", read5, err)
	}
	if err := client.ClearBridgePassword(ctx, read5, projectID); err != nil {
		t.Fatalf("ClearBridgePassword: %v", err)
	}

	if err := client.UpsertCredentials(ctx, read5, deviceID, hostname, projectID, admin, "Final#9", "ENABLED"); err != nil {
		t.Fatalf("UpsertCredentials: %v", err)
	}
	final, err := client.GetCredentials(ctx, deviceID, projectID, admin)
	if err != nil || final.OldPassword != "Final#9" || final.PendingPassword != "" || final.BridgePassword != "" {
		t.Fatalf("final = (%+v, %v)", final, err)
	}
}
