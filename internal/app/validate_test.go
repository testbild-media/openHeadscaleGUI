package app

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/testbild-media/openHeadscaleGUI/internal/config"
	"github.com/testbild-media/openHeadscaleGUI/internal/headscale"
	"github.com/testbild-media/openHeadscaleGUI/internal/store"
)

func TestValidDomain(t *testing.T) {
	good := []string{"vpn.example.com", "a.b.c.example.org", "x1.de"}
	bad := []string{"", "localhost", "-a.example.com", "a..b", "1.2.3.4", "exa mple.com", "a.123"}
	for _, d := range good {
		if err := ValidDomain(d); err != nil {
			t.Errorf("%q should be valid: %v", d, err)
		}
	}
	for _, d := range bad {
		if err := ValidDomain(d); err == nil {
			t.Errorf("%q should be invalid", d)
		}
	}
}

func TestPrefixes(t *testing.T) {
	if _, err := ValidPrefixV4("100.64.0.0/10"); err != nil {
		t.Error(err)
	}
	if _, err := ValidPrefixV4("10.0.0.0/8"); err == nil {
		t.Error("10/8 must be rejected")
	}
	if _, err := ValidPrefixV6("fd7a:115c:a1e0::/48"); err != nil {
		t.Error(err)
	}
}

func TestNodeNameAndAuthID(t *testing.T) {
	n, err := NodeName("Joe's MacBook Pro")
	if err != nil || n != "joes-macbook-pro" {
		t.Errorf("got %q %v", n, err)
	}
	id, ok := ParseAuthID("https://vpn.example.com/register/hskey-authreq-abcdefghijklmnopqrstuvwx")
	if !ok || !ValidAuthID(id) {
		t.Errorf("auth id not parsed: %q", id)
	}
	if ValidAuthID("hskey-authreq-short") {
		t.Error("short auth id accepted")
	}
}

func TestReservedIP(t *testing.T) {
	inst := &store.Instance{PrefixV4: "100.64.0.0/10", PrefixV6: "fd7a:115c:a1e0::/48"}
	if got := ReservedIPv4(inst); got != netip.MustParseAddr("100.64.0.1") {
		t.Errorf("reserved v4 = %s", got)
	}
	if got := ReservedIPv6(inst); got != netip.MustParseAddr("fd7a:115c:a1e0::1") {
		t.Errorf("reserved v6 = %s", got)
	}
}

func TestAdmitDERP(t *testing.T) {
	cfg := &config.Config{DataDir: t.TempDir(), AdminDomain: "admin.example.com", TLSMode: config.TLSModeOff}
	a, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	known := "nodekey:" + repeat("a", 64)
	unknown := "nodekey:" + repeat("b", 64)
	denied := "nodekey:" + repeat("c", 64)
	idx := map[string]int64{known: 1, denied: 1}
	a.derpIndex.Store(&idx)
	ctx := context.Background()
	if err := a.DB.SetDERPKey(ctx, &store.DERPKey{NodeKey: denied, Mode: "deny"}); err != nil {
		t.Fatal(err)
	}
	src := netip.MustParseAddr("203.0.113.5")
	if !a.admitDERP(known, src) {
		t.Error("known key rejected")
	}
	if a.admitDERP(unknown, src) {
		t.Error("unknown key admitted")
	}
	if a.admitDERP(denied, src) {
		t.Error("denylisted key admitted")
	}
	if err := a.DB.SetDERPKey(ctx, &store.DERPKey{NodeKey: unknown, Mode: "allow"}); err != nil {
		t.Fatal(err)
	}
	if !a.admitDERP(unknown, src) {
		t.Error("allowlisted key rejected")
	}
}

func repeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}

func TestForwardTargetAllowed(t *testing.T) {
	cfg := &config.Config{DataDir: t.TempDir(), AdminDomain: "admin.example.com", TLSMode: config.TLSModeOff}
	a, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	inst := &store.Instance{ID: 7, PrefixV4: "100.64.0.0/10", PrefixV6: "fd7a:115c:a1e0::/48"}
	a.nodes[7] = []headscale.Node{
		{ID: 1, ApprovedRoutes: []string{"192.168.50.0/24", "0.0.0.0/0", "::/0"}},
		{ID: 2, AvailableRoutes: []string{"10.10.0.0/16"}}, // advertised, not approved
	}
	cases := map[string]bool{
		"100.64.10.5":       true,
		"fd7a:115c:a1e0::5": true,
		"192.168.50.10":     true,  // approved subnet route
		"10.10.0.1":         false, // only advertised
		"8.8.8.8":           false, // exit route must not open the internet
		"127.0.0.1":         false,
		"169.254.169.254":   false,
		"10.0.0.1":          false,
	}
	for ip, want := range cases {
		if got := a.targetAllowed(inst, netip.MustParseAddr(ip)); got != want {
			t.Errorf("%s: got %v, want %v", ip, got, want)
		}
	}
}
