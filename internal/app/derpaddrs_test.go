package app

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/testbild-media/openHeadscaleGUI/internal/derp"
)

func TestPickDERPAddrs(t *testing.T) {
	addrs := []netip.Addr{
		netip.MustParseAddr("192.168.1.10"),          // split DNS on the server
		netip.MustParseAddr("100.64.0.1"),            // tailnet
		netip.MustParseAddr("::ffff:85.215.175.236"), // mapped
		netip.MustParseAddr("85.215.175.200"),
		netip.MustParseAddr("fd00::1"), // ULA
		netip.MustParseAddr("2a01:239:41c:f300::1"),
	}
	v4, v6 := pickDERPAddrs(addrs)
	if v4 != "85.215.175.200" || v6 != "2a01:239:41c:f300::1" {
		t.Fatalf("got %q %q", v4, v6)
	}
	if v4, v6 := pickDERPAddrs([]netip.Addr{netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("127.0.0.1")}); v4 != "" || v6 != "" {
		t.Errorf("private addresses picked: %q %q", v4, v6)
	}
}

func TestDERPAddrsAutomatic(t *testing.T) {
	a, inst := testApp(t)
	ctx := context.Background()
	if err := a.DB.SetSettings(ctx, map[string]string{SetDERPEnabled: "1", SetDERPDomain: "derp.example.com",
		SetDERPRegionID: "930", SetDERPRegionCode: "test", SetDERPRegionName: "Test"}); err != nil {
		t.Fatal(err)
	}
	inst.UseCentralDERP = true
	orig := derpLookup
	defer func() { derpLookup = orig }()
	answer, fail := []netip.Addr{netip.MustParseAddr("85.215.175.236")}, false
	derpLookup = func(_ context.Context, host string) ([]netip.Addr, error) {
		if host != "derp.example.com" {
			t.Errorf("looked up %q", host)
		}
		if fail {
			return nil, errors.New("lookup failed")
		}
		return answer, nil
	}

	if !a.refreshDERPAddrs(ctx) {
		t.Fatal("first lookup must report a change")
	}
	if a.refreshDERPAddrs(ctx) {
		t.Error("same answer reported as change")
	}
	m := string(a.derpMapFor(inst))
	if !strings.Contains(m, "ipv4: 85.215.175.236") || strings.Contains(m, "ipv6") {
		t.Fatalf("DERP map without the automatic address:\n%s", m)
	}
	ad := a.DERPAddrs(a.DERPSettings(ctx))
	if ad.IPv4 != "85.215.175.236" || ad.Source4 != "automatisch" || ad.Source6 != "" {
		t.Errorf("addrs = %+v", ad)
	}

	// a failed lookup keeps the last good address (no map change)
	fail = true
	if a.refreshDERPAddrs(ctx) {
		t.Error("failed lookup changed the addresses")
	}
	if ad := a.DERPAddrs(a.DERPSettings(ctx)); ad.IPv4 != "85.215.175.236" || ad.Auto.Err == "" {
		t.Errorf("after failure: %+v", ad)
	}

	// a configured address wins, "none" switches a family off
	if err := a.DB.SetSettings(ctx, map[string]string{SetDERPIPv4: "203.0.114.7", SetDERPIPv6: DERPAddrNone}); err != nil {
		t.Fatal(err)
	}
	fail = false
	answer = append(answer, netip.MustParseAddr("2a01:239:41c:f300::1"))
	a.refreshDERPAddrs(ctx)
	ad = a.DERPAddrs(a.DERPSettings(ctx))
	if ad.IPv4 != "203.0.114.7" || ad.Source4 != "manuell" || ad.IPv6 != DERPAddrNone {
		t.Errorf("configured addresses: %+v", ad)
	}
	if m := string(a.derpMapFor(inst)); !strings.Contains(m, "ipv6: none") || !strings.Contains(m, "ipv4: 203.0.114.7") {
		t.Errorf("map:\n%s", m)
	}

	// split DNS: only private answers → no address, devices resolve themselves
	if err := a.DB.SetSettings(ctx, map[string]string{SetDERPIPv4: "", SetDERPIPv6: ""}); err != nil {
		t.Fatal(err)
	}
	answer = []netip.Addr{netip.MustParseAddr("192.168.1.10")}
	a.refreshDERPAddrs(ctx)
	ad = a.DERPAddrs(a.DERPSettings(ctx))
	if ad.IPv4 != "" || ad.IPv6 != "" || ad.Auto.Err == "" {
		t.Errorf("private answer used: %+v", ad)
	}
	if m := string(a.derpMapFor(inst)); strings.Contains(m, "ipv4") {
		t.Errorf("private address in map:\n%s", m)
	}
}

func TestDERPAddrsOtherDomain(t *testing.T) {
	a, _ := testApp(t)
	a.derpAuto.Store(&derpAuto{Domain: "old.example.com", IPv4: "85.215.175.236"})
	if ad := a.DERPAddrs(derp.Settings{Domain: "derp.example.com"}); ad.IPv4 != "" {
		t.Errorf("address of another domain used: %+v", ad)
	}
}
