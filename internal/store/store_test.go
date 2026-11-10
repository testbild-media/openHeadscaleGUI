package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestStoreRoundtrip(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	u := &User{Username: "Alice", PasswordHash: "x", Role: RoleUser, MaxInstances: 2}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetUserByName(ctx, "alice"); err != nil || got.ID != u.ID {
		t.Fatalf("case-insensitive lookup failed: %v", err)
	}
	for i := 0; i < 5; i++ {
		if err := s.RecordLoginFailure(ctx, u.ID); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := s.GetUser(ctx, u.ID)
	if !got.Locked(time.Now()) {
		t.Error("account should be locked after 5 failures")
	}
	inst := &Instance{Slug: "a", Name: "A", OwnerID: u.ID, Domain: "vpn.example.com", Enabled: true, InternalPort: 42000,
		GatewayPort: 41641, PrefixV4: "100.64.0.0/10", PrefixV6: "fd7a:115c:a1e0::/48", IPAllocation: "sequential",
		BaseDomain: "a.internal", NodeExpiry: "0", EphemeralTimeout: "30m", GatewayExitNode: true}
	if err := s.CreateInstance(ctx, inst); err != nil {
		t.Fatal(err)
	}
	f := &Forward{InstanceID: inst.ID, Kind: ForwardTCP, PublicPort: 20001, TargetHost: "100.64.0.5", TargetPort: 22, Enabled: true}
	if err := s.CreateForward(ctx, f); err != nil {
		t.Fatal(err)
	}
	dup := &Forward{InstanceID: inst.ID, Kind: ForwardTCP, PublicPort: 20001, TargetHost: "100.64.0.6", TargetPort: 22}
	if err := s.CreateForward(ctx, dup); err == nil {
		t.Error("duplicate public port accepted")
	}
	ok, err := s.UpsertPending(ctx, &PendingRegistration{InstanceID: inst.ID, AuthID: "hskey-authreq-x"}, 1)
	if err != nil || !ok {
		t.Fatal("pending insert failed", err)
	}
	if ok, _ := s.UpsertPending(ctx, &PendingRegistration{InstanceID: inst.ID, AuthID: "hskey-authreq-y"}, 1); ok {
		t.Error("pending limit not enforced")
	}
	if err := s.SaveAuthKey(ctx, inst.ID, 7, []byte("sealed"), time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	if enc, err := s.GetAuthKey(ctx, inst.ID, 7); err != nil || string(enc) != "sealed" {
		t.Fatalf("stored key not readable: %q %v", enc, err)
	}
	if _, err := s.GetAuthKey(ctx, inst.ID+1, 7); err != ErrNotFound {
		t.Error("key visible for another instance")
	}
	_ = s.PurgeAuthKeys(ctx, time.Now().Add(2*time.Hour).Unix())
	if ids, _ := s.AuthKeyIDs(ctx, inst.ID); len(ids) != 0 {
		t.Error("expired key not purged")
	}
	if err := s.DeleteInstance(ctx, inst.ID); err != nil {
		t.Fatal(err)
	}
	if fw, _ := s.ListForwards(ctx, inst.ID); len(fw) != 0 {
		t.Error("forwards not deleted with instance")
	}
}
