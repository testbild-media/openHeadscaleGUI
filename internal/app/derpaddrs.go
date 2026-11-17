package app

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/testbild-media/openHeadscaleGUI/internal/derp"
	"github.com/testbild-media/openHeadscaleGUI/internal/store"
)

// The DERP map tells the devices the addresses of the relay. Without them a
// device has to resolve the DERP domain itself before every connection
// attempt (within 1.5 s) – a device whose resolver is broken or missing
// (e.g. /etc/resolv.conf without nameserver) then cannot reach the relay at
// all, although the coordination server keeps working through its own
// cache. ohg therefore resolves the domain itself and puts the public
// addresses into the map when none are configured.

// DERPAddrNone disables an address family in the DERP map.
const DERPAddrNone = "none"

// derpAuto is the result of the server's own lookup of the DERP domain.
type derpAuto struct {
	Domain     string
	IPv4, IPv6 string
	Resolved   time.Time
	Err        string
}

// derpLookup resolves a host name (replaceable in tests).
var derpLookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// nonPublic are ranges that must never be handed to devices on the
// internet (besides private, loopback and link-local addresses).
var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),   // CGNAT / tailnets
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking / bridge networks
	netip.MustParsePrefix("192.0.2.0/24"),    // documentation
	netip.MustParsePrefix("198.51.100.0/24"), // documentation
	netip.MustParsePrefix("203.0.113.0/24"),  // documentation
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
}

// publicAddr reports whether a resolved address is reachable from the
// internet. A domain that resolves to a private address on the server
// (split DNS) must not end up in the map: devices outside would dial it.
func publicAddr(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// pickDERPAddrs returns the first public IPv4 and IPv6 address (sorted, so
// DNS round robin does not change the map on every lookup).
func pickDERPAddrs(addrs []netip.Addr) (v4, v6 string) {
	list := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		list = append(list, a.Unmap())
	}
	slices.SortFunc(list, func(x, y netip.Addr) int { return x.Compare(y) })
	for _, a := range list {
		if !publicAddr(a) {
			continue
		}
		if a.Is4() && v4 == "" {
			v4 = a.String()
		}
		if a.Is6() && v6 == "" {
			v6 = a.String()
		}
	}
	return v4, v6
}

// refreshDERPAddrs looks up the DERP domain and reports whether the
// automatic addresses changed. A failed lookup keeps the last good result.
func (a *App) refreshDERPAddrs(ctx context.Context) bool {
	ds := a.DERPSettings(ctx)
	cur := a.derpAuto.Load()
	if cur == nil {
		cur = &derpAuto{}
	}
	next := &derpAuto{Domain: ds.Domain}
	if ds.Enabled && ds.Domain != "" {
		lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		addrs, err := derpLookup(lctx, ds.Domain)
		cancel()
		next.Resolved = time.Now()
		switch {
		case err != nil:
			next.Err = err.Error()
			if cur.Domain == ds.Domain {
				next.IPv4, next.IPv6 = cur.IPv4, cur.IPv6
			}
		default:
			next.IPv4, next.IPv6 = pickDERPAddrs(addrs)
			if next.IPv4 == "" && next.IPv6 == "" {
				next.Err = "die Domain löst nur auf nicht öffentliche Adressen auf"
			}
		}
	}
	a.derpAuto.Store(next)
	return cur.IPv4 != next.IPv4 || cur.IPv6 != next.IPv6
}

// DERPAddrs are the relay addresses that go into the DERP map.
type DERPAddrs struct {
	IPv4, IPv6 string // "" = devices resolve the domain, "none" = family off
	// Source4/6: "manuell", "automatisch" or "" (none known).
	Source4, Source6 string
	// Auto is the server's own lookup (for display).
	Auto derpAuto
}

// DERPAddrs combines the configured addresses with the automatic ones:
// a configured address (or "none") wins, otherwise the public address the
// server resolved for the DERP domain is used.
func (a *App) DERPAddrs(ds derp.Settings) DERPAddrs {
	var auto derpAuto
	if p := a.derpAuto.Load(); p != nil && p.Domain == ds.Domain {
		auto = *p
	}
	r := DERPAddrs{Auto: auto}
	pick := func(manual, automatic string) (string, string) {
		switch {
		case manual != "":
			return manual, "manuell"
		case automatic != "":
			return automatic, "automatisch"
		}
		return "", ""
	}
	r.IPv4, r.Source4 = pick(ds.IPv4, auto.IPv4)
	r.IPv6, r.Source6 = pick(ds.IPv6, auto.IPv6)
	return r
}

// snapshotDERP captures the DERP maps and configs of all instances.
func (a *App) snapshotDERP(insts []*store.Instance) (maps, cfgs map[int64][]byte) {
	maps, cfgs = map[int64][]byte{}, map[int64][]byte{}
	for _, i := range insts {
		maps[i.ID] = a.derpMapFor(i)
		cfgs[i.ID], _ = a.renderConfig(i)
	}
	return maps, cfgs
}

// restartChangedDERP restarts the enabled instances whose DERP map or
// config differs from the snapshot.
func (a *App) restartChangedDERP(insts []*store.Instance, oldMaps, oldCfgs map[int64][]byte) {
	for _, i := range insts {
		if !i.Enabled {
			continue
		}
		cfg, _ := a.renderConfig(i)
		if string(a.derpMapFor(i)) != string(oldMaps[i.ID]) || string(cfg) != string(oldCfgs[i.ID]) {
			if err := a.startInstance(i); err != nil {
				a.Log.Error("restarting instance after DERP change failed", "instance", i.Slug, "err", err)
			}
		}
	}
}

// updateDERPAddrs refreshes the automatic addresses and hands changed DERP
// maps to the instances (runs periodically).
func (a *App) updateDERPAddrs(ctx context.Context) {
	insts, err := a.DB.ListInstances(ctx, 0)
	if err != nil {
		return
	}
	oldMaps, oldCfgs := a.snapshotDERP(insts)
	if !a.refreshDERPAddrs(ctx) {
		return
	}
	auto := a.derpAuto.Load()
	a.Log.Info("DERP addresses changed", "ipv4", auto.IPv4, "ipv6", auto.IPv6)
	a.restartChangedDERP(insts, oldMaps, oldCfgs)
}
