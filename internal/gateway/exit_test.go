package gateway

import (
	"net/netip"
	"testing"
)

func TestExitDestinationAllowed(t *testing.T) {
	for addr, want := range map[string]bool{
		"1.1.1.1":              true,
		"89.22.104.140":        true, // public, incl. the server's own public IP
		"2606:4700:4700::1111": true,
		"::ffff:8.8.8.8":       true,
		"127.0.0.1":            false,
		"::1":                  false,
		"10.0.0.5":             false,
		"172.17.0.1":           false, // docker bridge
		"192.168.1.1":          false,
		"169.254.169.254":      false, // cloud metadata
		"fe80::1":              false,
		"100.64.0.1":           false, // tailnet / gateway itself
		"100.100.100.100":      false, // Tailscale service IP
		"fd7a:115c:a1e0::1":    false,
		"fd00::1":              false,
		"0.0.0.0":              false,
		"224.0.0.251":          false,
		"255.255.255.255":      false,
		"240.0.0.1":            false,
		"198.18.0.1":           false,
	} {
		if got := exitDestinationAllowed(netip.MustParseAddr(addr)); got != want {
			t.Errorf("%s: got %v, want %v", addr, got, want)
		}
	}
}
