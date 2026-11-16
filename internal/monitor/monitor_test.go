package monitor

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/ipn/ipnstate"

	"github.com/testbild-media/openHeadscaleGUI/internal/derp"
	"github.com/testbild-media/openHeadscaleGUI/internal/forward"
	"github.com/testbild-media/openHeadscaleGUI/internal/gateway"
	"github.com/testbild-media/openHeadscaleGUI/internal/headscale"
)

type fakeSource struct {
	nodes    []headscale.Node
	derp     []derp.Client
	expected bool
}

func (f *fakeSource) RunningInstances() []int64                   { return []int64{1} }
func (f *fakeSource) CachedNodes(int64) []headscale.Node          { return f.nodes }
func (f *fakeSource) GatewayNodeID(int64) uint64                  { return 1 }
func (f *fakeSource) DERPClients() []derp.Client                  { return f.derp }
func (f *fakeSource) DERPStats() derp.Stats                       { return derp.Stats{Running: true} }
func (f *fakeSource) ForwardCounters() map[int64]forward.Snapshot { return nil }
func (f *fakeSource) RelayExpected(int64) bool                    { return f.expected }
func (f *fakeSource) PeerStatus(context.Context, int64) (*ipnstate.Status, error) {
	return nil, errors.New("not needed")
}
func (f *fakeSource) Ping(context.Context, int64, netip.Addr) (*ipnstate.PingResult, error) {
	return nil, errors.New("not needed")
}

func TestRelayMissing(t *testing.T) {
	old := RelayGrace
	RelayGrace = 0
	defer func() { RelayGrace = old }()

	src := &fakeSource{expected: true, nodes: []headscale.Node{
		{ID: 1, NodeKey: "nodekey:gw", Online: true},       // the gateway itself
		{ID: 2, NodeKey: "nodekey:signage", Online: true},  // online, no relay
		{ID: 3, NodeKey: "nodekey:pc", Online: true},       // online with relay
		{ID: 4, NodeKey: "nodekey:offline", Online: false}, // offline: not a relay issue
	}, derp: []derp.Client{{Key: "nodekey:pc", Remote: "84.142.251.82:4793"}}}
	m := New(src, slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.sample(context.Background())

	v := m.Instance(1)
	if len(v.RelayMissing) != 1 || v.RelayMissing[0] != 2 {
		t.Fatalf("relay missing = %v, want [2]", v.RelayMissing)
	}
	if n := v.Nodes[2]; !n.RelayMissing || n.RelayMissingSince.IsZero() || n.DERPConnected {
		t.Errorf("node 2: %+v", n)
	}
	if v.Nodes[3].RelayMissing || !v.Nodes[3].DERPConnected {
		t.Error("node with relay reported")
	}
	if is := m.RelayIssues(); len(is) != 1 || is[0].InstanceID != 1 || is[0].NodeID != 2 {
		t.Errorf("issues = %+v", is)
	}

	// the device reconnects: the issue disappears
	src.derp = append(src.derp, derp.Client{Key: "nodekey:signage", Remote: "88.130.68.254:62925"})
	m.sample(context.Background())
	if v := m.Instance(1); len(v.RelayMissing) != 0 || len(m.RelayIssues()) != 0 {
		t.Errorf("still reported after reconnect: %v", v.RelayMissing)
	}

	// instances that may use the public relays are not judged
	src.derp = src.derp[:1]
	src.expected = false
	m.sample(context.Background())
	if v := m.Instance(1); len(v.RelayMissing) != 0 {
		t.Errorf("judged without central-only relay: %v", v.RelayMissing)
	}
}

func TestRelayGrace(t *testing.T) {
	src := &fakeSource{expected: true, nodes: []headscale.Node{{ID: 2, NodeKey: "nodekey:x", Online: true}}}
	m := New(src, slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.sample(context.Background())
	if v := m.Instance(1); len(v.RelayMissing) != 0 {
		t.Fatal("reported before the grace period (reconnect after a restart)")
	}
	// pretend the device has been missing for longer than the grace period
	m.mu.Lock()
	m.inst[1].nodes[2].relayMissingSince = time.Now().Add(-RelayGrace - time.Second)
	m.mu.Unlock()
	if v := m.Instance(1); len(v.RelayMissing) != 1 {
		t.Fatal("not reported after the grace period")
	}
}

func TestRelayMissingIgnoresServerNodes(t *testing.T) {
	old := RelayGrace
	RelayGrace = 0
	defer func() { RelayGrace = old }()
	// the gateway ID is not known yet (gateway still starting), but its node
	// belongs to the system user: never report the server itself
	src := &fakeSource{expected: true, nodes: []headscale.Node{
		{ID: 7, NodeKey: "nodekey:gw", Online: true, User: &headscale.User{Name: gateway.SystemUser}},
	}}
	m := New(src, slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.sample(context.Background())
	if v := m.Instance(1); len(v.RelayMissing) != 0 {
		t.Errorf("server node reported: %v", v.RelayMissing)
	}
}
