package app

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/testbild-media/openHeadscaleGUI/internal/config"
	"github.com/testbild-media/openHeadscaleGUI/internal/store"
)

// Forwards with LocalTarget reach services on the server itself (or its
// local networks such as Docker bridges) directly, not through a tailnet.
// Only superadmins may create them, and ohg's own internal listeners stay
// unreachable.

var tailnetV6 = netip.MustParsePrefix("fd7a:115c:a1e0::/48")

// localAddrs returns the addresses assigned to the server's interfaces.
var localAddrs = func() []netip.Addr {
	var out []netip.Addr
	ifs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, a := range ifs {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p.Addr().Unmap())
		}
	}
	return out
}

// isServerAddr reports whether addr belongs to the server itself.
func isServerAddr(addr netip.Addr) bool {
	if addr.IsLoopback() {
		return true
	}
	for _, a := range localAddrs() {
		if a == addr {
			return true
		}
	}
	return false
}

// internalPorts are ohg's own listeners on the server, which a forward must
// never expose: admin/edge listeners, the headscale instances, the DERP
// admission endpoint, STUN and the gateways' WireGuard ports.
func (a *App) internalPorts(ctx context.Context) map[string]bool {
	r := map[string]bool{}
	listeners := []string{a.Cfg.HTTPAddr}
	if a.Cfg.TLSMode != config.TLSModeOff { // behind a proxy only HTTPAddr is used
		listeners = append(listeners, a.Cfg.HTTPSAddr)
	}
	for _, addr := range listeners {
		if _, p, err := net.SplitHostPort(addr); err == nil {
			r["tcp/"+p] = true
		}
	}
	if a.DERP != nil && a.DERP.InternalPort() > 0 {
		r["tcp/"+strconv.Itoa(a.DERP.InternalPort())] = true
	}
	if ds := a.DERPSettings(ctx); ds.STUNPort > 0 {
		r["udp/"+strconv.Itoa(ds.STUNPort)] = true
	}
	insts, _ := a.DB.ListInstances(ctx, 0)
	for _, i := range insts {
		r["tcp/"+strconv.Itoa(i.InternalPort)] = true
		r["udp/"+strconv.Itoa(i.GatewayPort)] = true
	}
	return r
}

// localTarget validates the target of a forward to the server itself and
// returns the normalised address. proto is "tcp" or "udp".
func (a *App) localTarget(ctx context.Context, host string, port int, proto string) (netip.Addr, error) {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if strings.EqualFold(host, "localhost") || host == "" {
		host = "127.0.0.1"
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, Errf("Bitte eine IP-Adresse des Servers angeben, z. B. 127.0.0.1 oder 172.17.0.2 (Docker)")
	}
	addr = addr.Unmap()
	switch {
	case addr.IsUnspecified() || addr.IsMulticast() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast():
		return netip.Addr{}, Errf("Die Adresse %s ist als Ziel nicht erlaubt", addr)
	case tailnetV6.Contains(addr):
		return netip.Addr{}, Errf("%s ist eine Tailnet-Adresse – dafür ein Gerät oder eine Ziel-IP im Tailnet wählen", addr)
	case !addr.IsLoopback() && !addr.IsPrivate():
		return netip.Addr{}, Errf("„Dieser Server“ erlaubt nur lokale Adressen (127.0.0.1, ::1, private Netze wie Docker oder LAN), nicht %s", addr)
	}
	if isServerAddr(addr) && a.internalPorts(ctx)[proto+"/"+strconv.Itoa(port)] {
		return netip.Addr{}, Errf("Port %d wird von OpenHeadscaleGUI selbst verwendet und kann nicht weitergeleitet werden", port)
	}
	return addr, nil
}

// localDial connects to a service on the server itself.
func localDial(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// targetProto is the transport protocol used to reach the target of f.
func targetProto(kind string) string {
	if kind == store.ForwardUDP {
		return "udp"
	}
	return "tcp"
}
