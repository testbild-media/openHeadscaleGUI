package app

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/testbild-media/openHeadscaleGUI/internal/gateway"
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

	base := BridgeRequest{Mode: store.BridgePort, FromInstanceID: srv.ID, NodeID: 2, TargetPort: 22, Proto: "tcp", ToInstanceID: people.ID,
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

func TestHostBridge(t *testing.T) {
	a, people := testApp(t)
	ctx := context.Background()
	root := &store.User{Username: "root", PasswordHash: "x", Role: store.RoleSuperadmin}
	if err := a.DB.CreateUser(ctx, root); err != nil {
		t.Fatal(err)
	}
	super := Actor{User: root}
	people.MagicDNS, people.BaseDomain = true, "people.internal"
	if err := a.DB.UpdateInstance(ctx, people); err != nil {
		t.Fatal(err)
	}
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
		people.ID: {node(1, "ohg-gateway", "100.100.0.1"), node(2, "anna", "100.100.0.2"), node(3, "server-b", "100.100.0.3")},
	}
	a.gwNodeIDs = map[int64]uint64{srv.ID: 1, people.ID: 1}
	create := func(r BridgeRequest) (*store.Bridge, error) {
		if err := a.validateBridge(ctx, super, &r, 0); err != nil {
			return nil, err
		}
		b := &store.Bridge{}
		fillBridge(b, r)
		return b, a.DB.CreateBridge(ctx, b)
	}
	b1, err := create(BridgeRequest{FromInstanceID: srv.ID, NodeID: 2, ToInstanceID: people.ID, AllowedNodes: []int64{2}, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if !b1.IsHost() || b1.VirtualIP != "198.18.0.1" || b1.DNSName != "server-a" || b1.ListenPort != 0 || b1.Name != "server-a" {
		t.Errorf("host bridge: %+v", b1)
	}
	// server-b exists as a device name in people: the DNS label is suffixed
	b2, err := create(BridgeRequest{FromInstanceID: srv.ID, NodeID: 3, ToInstanceID: people.ID, AllowAll: true, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if b2.VirtualIP != "198.18.0.2" || b2.DNSName != "server-b-bridge" {
		t.Errorf("second host bridge: %+v", b2)
	}
	if _, err := create(BridgeRequest{FromInstanceID: srv.ID, NodeID: 2, ToInstanceID: people.ID, AllowAll: true}); err == nil {
		t.Error("same host bridged twice into one instance")
	}
	if _, err := create(BridgeRequest{FromInstanceID: srv.ID, NodeID: 3, ToInstanceID: people.ID, AllowAll: true, DNSName: "anna"}); err == nil {
		t.Error("DNS name of an existing device accepted")
	}

	a.Bridges = nil // no listeners in this test
	a.GW = gateway.NewManager(a.Log, false)
	bridges, _ := a.DB.ListBridges(ctx)
	insts, _ := a.DB.ListInstances(ctx, 0)
	a.syncHostBridges(ctx, bridges, insts)
	if p, ok := a.wantsBridgeRoute(people); !ok || p.String() != "198.18.0.0/24" {
		t.Errorf("bridge route not wanted: %v %v", p, ok)
	}
	if _, ok := a.wantsBridgeRoute(srv); ok {
		t.Error("route wanted for an instance without host bridges")
	}
	bi := bridgeInterceptor{a: a, inst: people.ID}
	ap := func(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }
	if h, ok := bi.TCP(ap("100.100.0.2:5000"), ap("198.18.0.1:22")); !ok || h == nil {
		t.Error("anna not admitted to server-a")
	}
	if h, ok := bi.TCP(ap("100.100.0.3:5000"), ap("198.18.0.1:22")); !ok || h != nil {
		t.Error("server-b (people) admitted to server-a")
	}
	if h, ok := bi.UDP(ap("100.100.0.3:5000"), ap("198.18.0.2:53")); !ok || h == nil {
		t.Error("allow-all bridge rejects a client")
	}
	if _, ok := bi.TCP(ap("100.100.0.2:5000"), ap("198.18.0.9:22")); !ok {
		t.Error("unknown address in the bridge network must be rejected, not passed on")
	}
	if _, ok := bi.TCP(ap("100.100.0.2:5000"), ap("1.1.1.1:443")); ok {
		t.Error("internet traffic taken by the bridge interceptor")
	}
	recs, _ := os.ReadFile(filepath.Join(a.InstanceDir(people.Slug), extraRecordsFile))
	for _, want := range []string{`"server-a.people.internal"`, `"198.18.0.1"`, `"server-b-bridge.people.internal"`} {
		if !strings.Contains(string(recs), want) {
			t.Errorf("DNS records miss %s: %s", want, recs)
		}
	}
	if !strings.Contains(IsolatedPolicy(people), `"198.18.0.0/24:*"`) {
		t.Error("isolation policy does not allow the bridge network")
	}
}

func TestValidBridgePrefix(t *testing.T) {
	for in, ok := range map[string]bool{"198.18.0.0/24": true, "10.99.0.0/16": true, "192.168.250.0/24": true,
		"100.100.0.0/24": false, "8.8.8.0/24": false, "10.0.0.0/8": false, "10.1.1.0/30": false, "fd00::/64": false, "x": false} {
		if _, err := ValidBridgePrefix(in); (err == nil) != ok {
			t.Errorf("%s: err=%v", in, err)
		}
	}
}
