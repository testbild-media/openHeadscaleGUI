package gateway

import (
	"errors"
	"net"
	"net/netip"

	"tailscale.com/tsnet"
	"tailscale.com/types/nettype"
	"tailscale.com/wgengine/netstack"
)

// exitBlocked lists destinations exit-node clients must never reach through
// the server, in addition to loopback, link-local, multicast and private
// networks (see exitDestinationAllowed).
var exitBlocked = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), // CGNAT / tailnet addresses
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
}

// exitDestinationAllowed reports whether traffic of an exit-node client may
// be forwarded to addr: only public unicast addresses, never the server's
// loopback, private or link-local networks (e.g. cloud metadata services)
// or tailnet addresses.
func exitDestinationAllowed(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return false
	}
	for _, p := range exitBlocked {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

// installExitForwarding lets the gateway act as a working exit node.
//
// tsnet only accepts flows for its own listeners and rejects everything
// else, so traffic of clients using the server as exit node was dropped.
// The wrapped hooks hand flows to public destinations back to netstack,
// which forwards them to the internet like tailscaled in userspace mode.
// Flows for the gateway's own addresses keep tsnet's behaviour. Must be
// called after srv.Start and before the node comes up.
func installExitForwarding(srv *tsnet.Server, enabled func() bool) error {
	sys := srv.Sys()
	if sys == nil {
		return errors.New("tsnet system not initialised")
	}
	impl, ok := sys.Netstack.GetOK()
	if !ok {
		return errors.New("netstack not available")
	}
	ns, ok := impl.(*netstack.Impl)
	if !ok {
		return errors.New("unexpected netstack implementation")
	}
	tcp, udp := ns.GetTCPHandlerForFlow, ns.GetUDPHandlerForFlow
	if tcp == nil || udp == nil {
		return errors.New("netstack flow hooks missing")
	}
	ns.GetTCPHandlerForFlow = func(src, dst netip.AddrPort) (func(net.Conn), bool) {
		h, intercept := tcp(src, dst)
		if h == nil && enabled() && exitDestinationAllowed(dst.Addr()) {
			return nil, false // netstack forwards it
		}
		return h, intercept
	}
	ns.GetUDPHandlerForFlow = func(src, dst netip.AddrPort) (func(nettype.ConnPacketConn), bool) {
		h, intercept := udp(src, dst)
		if h == nil && enabled() && exitDestinationAllowed(dst.Addr()) {
			return nil, false
		}
		return h, intercept
	}
	return nil
}
