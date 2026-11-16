package app

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/testbild-media/openHeadscaleGUI/internal/config"
	"github.com/testbild-media/openHeadscaleGUI/internal/store"
)

func testApp(t *testing.T) (*App, *store.Instance) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "ohg.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ctx := context.Background()
	owner := &store.User{Username: "owner", PasswordHash: "x", Role: store.RoleUser}
	if err := db.CreateUser(ctx, owner); err != nil {
		t.Fatal(err)
	}
	inst := &store.Instance{Slug: "a", Name: "A", OwnerID: owner.ID, Domain: "vpn.example.com", Enabled: true, InternalPort: 42000,
		GatewayPort: 41641, PrefixV4: "100.64.0.0/10", PrefixV6: "fd7a:115c:a1e0::/48", IPAllocation: "sequential",
		BaseDomain: "a.internal", NodeExpiry: "0", EphemeralTimeout: "30m"}
	if err := db.CreateInstance(ctx, inst); err != nil {
		t.Fatal(err)
	}
	return &App{DB: db, Cfg: &config.Config{AdminDomain: "admin.example.com", HTTPAddr: "127.0.0.1:8480", HTTPSAddr: ":443"}}, inst
}

func TestLocalTarget(t *testing.T) {
	a, _ := testApp(t)
	orig := localAddrs
	localAddrs = func() []netip.Addr {
		return []netip.Addr{netip.MustParseAddr("172.17.0.1"), netip.MustParseAddr("192.168.1.5")}
	}
	defer func() { localAddrs = orig }()
	ctx := context.Background()
	for _, c := range []struct {
		host  string
		port  int
		proto string
		want  string // "" = error
	}{
		{"localhost", 9000, "tcp", "127.0.0.1"},
		{"127.0.0.1", 9000, "tcp", "127.0.0.1"},
		{"[::1]", 9000, "tcp", "::1"},
		{"172.17.0.2", 80, "tcp", "172.17.0.2"},      // docker container
		{"192.168.1.20", 443, "tcp", "192.168.1.20"}, // other LAN host: ohg's ports do not matter there
		{"127.0.0.1", 8480, "tcp", ""},               // ohg's own listener
		{"127.0.0.1", 443, "tcp", ""},
		{"172.17.0.1", 443, "tcp", ""}, // server's own docker bridge address
		{"192.168.1.5", 8480, "tcp", ""},
		{"127.0.0.1", 42000, "tcp", ""}, // headscale of an instance
		{"127.0.0.1", 41641, "udp", ""}, // gateway WireGuard
		{"127.0.0.1", 41641, "tcp", "127.0.0.1"},
		{"169.254.169.254", 80, "tcp", ""}, // cloud metadata
		{"100.64.0.5", 80, "tcp", ""},      // tailnet
		{"fd7a:115c:a1e0::5", 80, "tcp", ""},
		{"8.8.8.8", 53, "udp", ""}, // public address
		{"0.0.0.0", 80, "tcp", ""},
		{"nas.local", 80, "tcp", ""}, // names are not resolved
	} {
		got, err := a.localTarget(ctx, c.host, c.port, c.proto)
		if c.want == "" {
			if err == nil {
				t.Errorf("%s:%d/%s allowed (%s), want error", c.host, c.port, c.proto, got)
			}
			continue
		}
		if err != nil || got.String() != c.want {
			t.Errorf("%s:%d/%s: %v %v, want %s", c.host, c.port, c.proto, got, err, c.want)
		}
	}
}

func TestValidateForwardLocalAndRedirect(t *testing.T) {
	a, inst := testApp(t)
	ctx := context.Background()
	owner, _ := a.DB.GetUser(ctx, inst.OwnerID)
	super := &store.User{ID: 99, Username: "root", Role: store.RoleSuperadmin}
	userActor, superActor := Actor{User: owner}, Actor{User: super}

	local := ForwardRequest{Kind: store.ForwardHTTP, Domain: "os.example.com", Local: true, TargetHost: "127.0.0.1", TargetPort: 9000, Enabled: true}
	r := local
	if err := a.validateForward(ctx, userActor, inst, &r, nil); err == nil {
		t.Error("normal user may create a forward to the server itself")
	}
	r = local
	if err := a.validateForward(ctx, superActor, inst, &r, nil); err != nil || r.TargetHost != "127.0.0.1" || r.NodeID != 0 {
		t.Errorf("superadmin local forward: %v %+v", err, r)
	}
	f := &store.Forward{InstanceID: inst.ID, LocalTarget: true}
	if a.canManageForward(userActor, inst, f) || !a.canManageForward(superActor, inst, f) {
		t.Error("only superadmins may change local forwards")
	}

	red := ForwardRequest{Kind: store.ForwardRedirect, Domain: "web.example.com", RedirectURL: "https://www.google.com", TargetPort: 80,
		NodeID: 5, BasicAuthUser: "x", Enabled: true}
	r = red
	if err := a.validateForward(ctx, superActor, inst, &r, nil); err != nil {
		t.Fatal(err)
	}
	if r.RedirectCode != 302 || r.TargetPort != 0 || r.NodeID != 0 || r.BasicAuthUser != "" || r.RedirectURL != "https://www.google.com" {
		t.Errorf("redirect not normalised: %+v", r)
	}
	for _, bad := range []ForwardRequest{
		{Kind: store.ForwardRedirect, Domain: "web.example.com", RedirectURL: "www.google.com"},
		{Kind: store.ForwardRedirect, Domain: "web.example.com", RedirectURL: "javascript:alert(1)"},
		{Kind: store.ForwardRedirect, Domain: "web.example.com", RedirectURL: "https://web.example.com/"},
		{Kind: store.ForwardRedirect, Domain: "web.example.com", RedirectURL: "https://x.org", RedirectCode: 200},
		{Kind: store.ForwardRedirect, Domain: "admin.example.com", RedirectURL: "https://x.org"},
	} {
		b := bad
		if err := a.validateForward(ctx, superActor, inst, &b, nil); err == nil {
			t.Errorf("accepted invalid redirect %+v", bad)
		}
	}
}
