package app

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/testbild-media/openHeadscaleGUI/internal/headscale"
	"github.com/testbild-media/openHeadscaleGUI/internal/store"
)

func TestBridgeValidationAndAdmission(t *testing.T) {
	a, people := testApp(t) // owned by "owner"
	ctx := context.Background()
	owner, _ := a.DB.GetUser(ctx, people.OwnerID)
	root := &store.User{Username: "root", PasswordHash: "x", Role: store.RoleSuperadmin}
	if err := a.DB.CreateUser(ctx, root); err != nil {
		t.Fatal(err)
	}
	super := Actor{User: root}
	srv := &store.Instance{Slug: "srv", Name: "Server", OwnerID: root.ID, Domain: "srv.example.com", Enabled: true, InternalPort: 42001,
		GatewayPort: 41642, PrefixV4: "100.64.0.0/10", PrefixV6: "fd7a:115c:a1e0::/48", IPAllocation: "sequential",
		BaseDomain: "srv.internal", NodeExpiry: "0", EphemeralTimeout: "30m"}
	if err := a.DB.CreateInstance(ctx, srv); err != nil {
		t.Fatal(err)
	}
	node := func(id int, name, ip string) headscale.Node {
		return headscale.Node{ID: headscale.U64(id), GivenName: name, IPAddresses: []string{ip}}
	}
	a.nodes = map[int64][]headscale.Node{
		srv.ID:    {node(1, "ohg-gateway", "100.64.0.1"), node(2, "server-a", "100.64.0.2"), node(3, "server-b", "100.64.0.3")},
		people.ID: {node(1, "ohg-gateway", "100.64.0.1"), node(2, "anna", "100.64.0.2"), node(3, "bert", "100.64.0.3")},
	}
	a.gwNodeIDs = map[int64]uint64{srv.ID: 1, people.ID: 1}

	base := BridgeRequest{FromInstanceID: srv.ID, NodeID: 2, TargetPort: 22, Proto: "tcp", ToInstanceID: people.ID,
		ListenPort: 2201, AllowedNodes: []int64{2, 2}, Enabled: true}
	r := base
	if err := a.validateBridge(ctx, super, &r, 0); err != nil {
		t.Fatal(err)
	}
	if r.Name != "server-a:22" || len(r.AllowedNodes) != 1 {
		t.Errorf("not normalised: %+v", r)
	}
	// the owner of only one end may not bridge into it
	r = base
	if err := a.validateBridge(ctx, Actor{User: owner}, &r, 0); err != ErrForbidden {
		t.Errorf("owner of one instance: %v", err)
	}
	for name, mod := range map[string]func(*BridgeRequest){
		"same instance":     func(r *BridgeRequest) { r.ToInstanceID = r.FromInstanceID },
		"gateway as source": func(r *BridgeRequest) { r.NodeID = 1 },
		"unknown source":    func(r *BridgeRequest) { r.NodeID = 9 },
		"public IP":         func(r *BridgeRequest) { r.NodeID, r.TargetHost = 0, "8.8.8.8" },
		"nobody allowed":    func(r *BridgeRequest) { r.AllowedNodes = nil },
		"gateway allowed":   func(r *BridgeRequest) { r.AllowedNodes = []int64{1} },
		"unknown client":    func(r *BridgeRequest) { r.AllowedNodes = []int64{7} },
		"bad port":          func(r *BridgeRequest) { r.ListenPort = 0 },
		"bad proto":         func(r *BridgeRequest) { r.Proto = "icmp" },
	} {
		r := base
		mod(&r)
		if err := a.validateBridge(ctx, super, &r, 0); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	r = base
	r.NodeID, r.TargetHost = 0, "100.64.0.3"
	if err := a.validateBridge(ctx, super, &r, 0); err != nil {
		t.Errorf("tailnet IP as source: %v", err)
	}

	b, err := a.CreateBridgeForTest(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	dup := base
	if err := a.validateBridge(ctx, super, &dup, 0); err == nil || !strings.Contains(err.Error(), "belegt") {
		t.Errorf("port collision not detected: %v", err)
	}
	if tgt, err := a.BridgeTarget(b); err != nil || tgt != "100.64.0.2:22" {
		t.Errorf("target: %q %v", tgt, err)
	}
	for ip, want := range map[string]bool{"100.64.0.2": true, "100.64.0.3": false, "100.64.0.1": false, "100.64.0.9": false} {
		if got := a.bridgeAdmits(b, netip.MustParseAddr(ip)); got != want {
			t.Errorf("admit %s = %v, want %v", ip, got, want)
		}
	}
	b.AllowAll = true
	if !a.bridgeAdmits(b, netip.MustParseAddr("100.64.0.3")) || a.bridgeAdmits(b, netip.MustParseAddr("100.64.0.1")) {
		t.Error("allow-all must admit every client but not the server node")
	}
}

func TestIsolatedPolicy(t *testing.T) {
	inst := &store.Instance{PrefixV4: "100.100.0.0/22", PrefixV6: "fd7a:115c:a1e0:ab::/64"}
	p := IsolatedPolicy(inst)
	for _, want := range []string{isolationMarker, `"ohg-system@"`, `"100.100.0.1/32:*"`, `"fd7a:115c:a1e0:ab::1/128:*"`} {
		if !strings.Contains(p, want) {
			t.Errorf("policy misses %s:\n%s", want, p)
		}
	}
	if strings.Contains(p, `"dst": ["*:*"]}, {"action": "accept", "src": ["*"]`) {
		t.Error("clients may reach each other")
	}
}

// CreateBridgeForTest stores a bridge without the listener sync.
func (a *App) CreateBridgeForTest(ctx context.Context, r BridgeRequest) (*store.Bridge, error) {
	if err := a.validateBridge(ctx, Actor{User: &store.User{ID: 99, Role: store.RoleSuperadmin}}, &r, 0); err != nil {
		return nil, err
	}
	b := &store.Bridge{}
	fillBridge(b, r)
	return b, a.DB.CreateBridge(ctx, b)
}
