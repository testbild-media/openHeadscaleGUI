package app

import (
	"net/netip"
	"testing"
	"time"

	"github.com/testbild-media/openHeadscaleGUI/internal/derp"
	"github.com/testbild-media/openHeadscaleGUI/internal/store"
)

func TestUDPCheck(t *testing.T) {
	own := netip.MustParseAddr("85.215.175.236")
	isLocal := func(a netip.Addr) bool { return a.IsLoopback() || a == own }
	start := time.Date(2026, 11, 16, 6, 0, 0, 0, time.UTC)
	later := start.Add(10 * time.Minute)
	clients := []derp.Client{
		{Remote: "[::ffff:85.215.175.236]:39362"}, // the server's own gateway
		{Remote: "[::ffff:88.130.68.254]:64880"},
		{Remote: "88.130.68.254:62925"},
		{Remote: "[2003:ce:736:1900::1550]:4793"},
	}
	st := derp.Stats{Running: true, STUNRunning: true, STUNSince: start, STUNInternal: 40, STUNExternal6: 3}

	// the situation on the user's server: IPv4 STUN never arrives
	c := udpCheck(st, clients, isLocal, later)
	if !c.Known || !c.Blocked4 || c.Blocked6 || c.Clients4 != 2 || c.Clients6 != 1 {
		t.Fatalf("blocked IPv4 not detected: %+v", c)
	}
	if c.Families() != "IPv4" || c.BlockedClients() != 2 {
		t.Errorf("families %q, clients %d", c.Families(), c.BlockedClients())
	}
	// once a request from outside arrived, everything is fine
	st.STUNExternal4 = 1
	if c := udpCheck(st, clients, isLocal, later); !c.Known || c.Blocked() {
		t.Errorf("open UDP reported as blocked: %+v", c)
	}
	st.STUNExternal4 = 0
	// too early for a conclusion
	if c := udpCheck(st, clients, isLocal, start.Add(time.Minute)); c.Known || c.Blocked() {
		t.Errorf("judged too early: %+v", c)
	}
	// only the server's own nodes use the relay: nothing to judge
	if c := udpCheck(st, clients[:1], isLocal, later); c.Known || c.Blocked() {
		t.Errorf("judged without external clients: %+v", c)
	}
	// STUN off: no conclusion
	st.STUNRunning = false
	if c := udpCheck(st, clients, isLocal, later); c.Known {
		t.Errorf("judged without STUN: %+v", c)
	}
}

func TestPortList(t *testing.T) {
	for want, in := range map[string][]int{
		"":             nil,
		"41641":        {41641},
		"41641–41643":  {41643, 41641, 41642},
		"41641, 41650": {41650, 41641},
		"41641–41642":  {41641, 41642, 41642},
	} {
		if got := portList(in); got != want {
			t.Errorf("portList(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestRelayOnlyCentral(t *testing.T) {
	inst := &store.Instance{Enabled: true, UseCentralDERP: true}
	if !relayOnlyCentral(inst, true) {
		t.Error("central-only instance")
	}
	if relayOnlyCentral(inst, false) {
		t.Error("relay not running")
	}
	inst.UsePublicDERP = true
	if relayOnlyCentral(inst, true) {
		t.Error("with the public relays a device may have its home elsewhere")
	}
	inst.UsePublicDERP, inst.UseCentralDERP = false, false
	if relayOnlyCentral(inst, true) {
		t.Error("instance without central DERP")
	}
}
