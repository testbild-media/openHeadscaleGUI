package store

import (
	"context"
	"database/sql"
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

// An existing database (schema v2) keeps its forwards when migration 3
// rebuilds the table, and several redirects (port 0) may coexist.
func TestMigrationKeepsForwards(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "old.db")
	raw, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range migrations[:2] {
		if _, err := raw.Exec(m); err != nil {
			t.Fatal(err)
		}
	}
	mustExec := func(q string, args ...any) {
		if _, err := raw.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	mustExec(`INSERT INTO users(id,username,password_hash,role,created_at,updated_at) VALUES(1,'a','x','superadmin',1,1)`)
	mustExec(`INSERT INTO instances(id,slug,name,owner_id,domain,enabled,internal_port,gateway_port,prefix_v4,prefix_v6,ip_allocation,base_domain,node_expiry,ephemeral_timeout,created_at,updated_at)
		VALUES(1,'a','A',1,'vpn.example.com',1,42000,41641,'100.64.0.0/10','fd7a:115c:a1e0::/48','sequential','a.internal','0','30m',1,1)`)
	mustExec(`INSERT INTO forwards(instance_id,kind,domain,public_port,node_id,target_host,target_port,created_at,updated_at)
		VALUES(1,'http','nas.example.com',0,7,'',5000,1,1)`)
	mustExec(`INSERT INTO forwards(instance_id,kind,public_port,target_host,target_port,created_at,updated_at)
		VALUES(1,'tcp',20022,'100.64.0.9',22,1,1)`)
	mustExec(`PRAGMA user_version = 2`)
	raw.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	fw, err := s.ListForwards(ctx, 1)
	if err != nil || len(fw) != 2 {
		t.Fatalf("forwards after migration: %v %v", fw, err)
	}
	for _, f := range fw {
		if f.LocalTarget || f.RedirectURL != "" || f.RedirectCode != 302 || !f.RedirectKeepPath {
			t.Errorf("unexpected defaults: %+v", f)
		}
	}
	for _, d := range []string{"a.example.com", "b.example.com"} {
		r := &Forward{InstanceID: 1, Kind: ForwardRedirect, Domain: d, RedirectURL: "https://www.example.org", RedirectCode: 301, Enabled: true}
		if err := s.CreateForward(ctx, r); err != nil {
			t.Fatalf("redirect %s: %v", d, err)
		}
	}
	got, _ := s.ListForwards(ctx, 1)
	if len(got) != 4 {
		t.Fatalf("want 4 forwards, got %d", len(got))
	}
	// instance delete still cascades after the rebuild
	if err := s.DeleteInstance(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if left, _ := s.ListForwards(ctx, 0); len(left) != 0 {
		t.Error("forwards not deleted with instance after rebuild")
	}
}

func TestBridges(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "b.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	u := &User{Username: "root", PasswordHash: "x", Role: RoleSuperadmin}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	mk := func(slug string, port int, isolate bool) *Instance {
		i := &Instance{Slug: slug, Name: slug, OwnerID: u.ID, Domain: slug + ".example.com", Enabled: true, InternalPort: port,
			GatewayPort: port - 400, PrefixV4: "100.64.0.0/10", PrefixV6: "fd7a:115c:a1e0::/48", IPAllocation: "sequential",
			BaseDomain: slug + ".internal", NodeExpiry: "0", EphemeralTimeout: "30m", IsolateClients: isolate}
		if err := s.CreateInstance(ctx, i); err != nil {
			t.Fatal(err)
		}
		return i
	}
	srv, people := mk("server", 42000, false), mk("people", 42001, true)
	if got, _ := s.GetInstance(ctx, people.ID); !got.IsolateClients {
		t.Error("isolation flag not stored")
	}
	b := &Bridge{Name: "Server A SSH", FromInstanceID: srv.ID, NodeID: 5, TargetPort: 22, Proto: "tcp", ToInstanceID: people.ID,
		ListenPort: 2201, AllowedNodes: []int64{3, 4}, Enabled: true}
	if err := s.CreateBridge(ctx, b); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetBridge(ctx, b.ID)
	if err != nil || !got.Allows(3) || !got.Allows(4) || got.Allows(5) || got.ListenPort != 2201 {
		t.Fatalf("bridge roundtrip: %+v %v", got, err)
	}
	dup := *b
	if err := s.CreateBridge(ctx, &dup); err == nil {
		t.Error("two bridges on the same port of one instance")
	}
	udp := *b
	udp.Proto = "udp"
	if err := s.CreateBridge(ctx, &udp); err != nil {
		t.Errorf("udp on the same port number: %v", err)
	}
	if err := s.DeleteInstance(ctx, srv.ID); err != nil {
		t.Fatal(err)
	}
	if left, _ := s.ListBridges(ctx); len(left) != 0 {
		t.Errorf("bridges not removed with their instance: %d", len(left))
	}
}

// Forwards to the server itself (v0.2–v0.5, bound to an instance) become
// server forwards: no instance any more, so deleting it keeps them.
func TestMigrationMovesLocalForwards(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "old.db")
	raw, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range migrations[:6] {
		if _, err := raw.Exec(m); err != nil {
			t.Fatal(err)
		}
	}
	for _, q := range []string{
		`INSERT INTO users(id,username,password_hash,role,created_at,updated_at) VALUES(1,'root','x','superadmin',1,1)`,
		`INSERT INTO instances(id,slug,name,owner_id,domain,enabled,internal_port,gateway_port,prefix_v4,prefix_v6,ip_allocation,base_domain,node_expiry,ephemeral_timeout,created_at,updated_at)
			VALUES(1,'a','A',1,'vpn.example.com',0,42000,41641,'100.64.0.0/10','fd7a:115c:a1e0::/48','sequential','a.internal','0','30m',1,1)`,
		`INSERT INTO forwards(id,instance_id,kind,domain,node_id,target_port,created_at,updated_at) VALUES(10,1,'http','nas.example.com',7,5000,1,1)`,
		`INSERT INTO forwards(id,instance_id,kind,domain,target_host,target_port,local_target,basic_auth_user,basic_auth_hash,allow_cidrs,description,created_at,updated_at)
			VALUES(11,1,'http','os.example.com','127.0.0.1',8080,1,'admin','$argon2id$x','10.0.0.0/8','Signage',1,2)`,
		`INSERT INTO forwards(id,instance_id,kind,public_port,target_host,target_port,local_target,enabled,created_at,updated_at)
			VALUES(12,1,'tcp',25565,'172.17.0.2',25565,1,0,1,1)`,
		`PRAGMA user_version = 6`,
	} {
		if _, err := raw.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	raw.Close()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	srv, err := s.ListForwards(ctx, ServerForwards)
	if err != nil || len(srv) != 2 {
		t.Fatalf("server forwards after migration: %+v %v", srv, err)
	}
	byID := map[int64]*Forward{}
	for _, f := range srv {
		if f.InstanceID != 0 || !f.LocalTarget {
			t.Errorf("forward %d not moved: %+v", f.ID, f)
		}
		byID[f.ID] = f
	}
	if f := byID[11]; f == nil || f.Domain != "os.example.com" || f.TargetHost != "127.0.0.1" || f.TargetPort != 8080 ||
		f.BasicAuthUser != "admin" || f.BasicAuthHash != "$argon2id$x" || f.AllowCIDRs != "10.0.0.0/8" || f.Description != "Signage" || f.UpdatedAt != 2 {
		t.Errorf("HTTPS server forward changed: %+v", f)
	}
	if f := byID[12]; f == nil || f.Kind != ForwardTCP || f.PublicPort != 25565 || f.Enabled {
		t.Errorf("TCP server forward changed: %+v", f)
	}
	if in, _ := s.ListForwards(ctx, 1); len(in) != 1 || in[0].ID != 10 || in[0].InstanceID != 1 {
		t.Errorf("instance forwards after migration: %+v", in)
	}
	if all, _ := s.ListForwards(ctx, 0); len(all) != 3 {
		t.Errorf("all forwards: %d", len(all))
	}
	// unique indexes still apply across both kinds
	if err := s.CreateForward(ctx, &Forward{Kind: ForwardTCP, PublicPort: 25565, TargetHost: "127.0.0.1", TargetPort: 1, LocalTarget: true}); err == nil {
		t.Error("second forward on tcp/25565 accepted")
	}
	// the database keeps "no instance" and "local target" together
	if err := s.CreateForward(ctx, &Forward{InstanceID: 1, Kind: ForwardTCP, PublicPort: 20000, TargetHost: "127.0.0.1", TargetPort: 1, LocalTarget: true}); err == nil {
		t.Error("local target inside an instance accepted")
	}
	if err := s.DeleteInstance(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if left, _ := s.ListForwards(ctx, 0); len(left) != 2 {
		t.Errorf("after deleting the instance: %d forwards left, want the 2 server forwards", len(left))
	}
}

// Redirects created as forwards (v0.2–v0.4) move to their own table.
func TestMigrationMovesRedirects(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "old.db")
	raw, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range migrations[:5] {
		if _, err := raw.Exec(m); err != nil {
			t.Fatal(err)
		}
	}
	for _, q := range []string{
		`INSERT INTO users(id,username,password_hash,role,created_at,updated_at) VALUES(7,'anna','x','user',1,1)`,
		`INSERT INTO instances(id,slug,name,owner_id,domain,enabled,internal_port,gateway_port,prefix_v4,prefix_v6,ip_allocation,base_domain,node_expiry,ephemeral_timeout,created_at,updated_at)
			VALUES(1,'a','A',7,'vpn.example.com',1,42000,41641,'100.64.0.0/10','fd7a:115c:a1e0::/48','sequential','a.internal','0','30m',1,1)`,
		`INSERT INTO forwards(instance_id,kind,domain,target_port,redirect_url,redirect_code,redirect_keep_path,allow_cidrs,description,created_at,updated_at)
			VALUES(1,'redirect','web.example.com',0,'https://www.example.org',301,0,'10.0.0.0/8','alt',1,1)`,
		`INSERT INTO forwards(instance_id,kind,domain,target_port,created_at,updated_at) VALUES(1,'http','nas.example.com',5000,1,1)`,
		`PRAGMA user_version = 5`,
	} {
		if _, err := raw.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	raw.Close()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	reds, err := s.ListRedirects(ctx, 0)
	if err != nil || len(reds) != 1 {
		t.Fatalf("redirects after migration: %v %v", reds, err)
	}
	r := reds[0]
	if r.OwnerID != 7 || r.Domain != "web.example.com" || r.URL != "https://www.example.org" || r.Code != 301 || r.KeepPath ||
		r.AllowCIDRs != "10.0.0.0/8" || !r.Enabled || r.Description != "alt" {
		t.Errorf("redirect not moved correctly: %+v", r)
	}
	if fw, _ := s.ListForwards(ctx, 0); len(fw) != 1 || fw[0].Kind != ForwardHTTP {
		t.Errorf("forwards after migration: %+v", fw)
	}
	dup := &Redirect{OwnerID: 7, Domain: "web.example.com", URL: "https://x.org", Code: 302}
	if err := s.CreateRedirect(ctx, dup); err == nil {
		t.Error("duplicate redirect domain accepted")
	}
}
