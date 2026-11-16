package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/testbild-media/openHeadscaleGUI/internal/forward"
	"github.com/testbild-media/openHeadscaleGUI/internal/gateway"
	"github.com/testbild-media/openHeadscaleGUI/internal/store"
	"tailscale.com/types/nettype"
)

// Host bridges make a whole device of instance A reachable in instance B:
// it gets a virtual address from B's bridge network, the server node of B
// advertises that network as a route, and every TCP/UDP flow to the
// virtual address (any port) is relayed through the server node of A to
// the real device – but only for the devices selected in the bridge.

// hostIndex is the in-memory view of host bridges used per flow.
type hostIndex struct {
	prefix map[int64]netip.Prefix                 // bridge network per instance
	hosts  map[int64]map[netip.Addr]*store.Bridge // instance -> virtual IP -> bridge
}

func (a *App) hostIdx() *hostIndex {
	if idx := a.hostBridges.Load(); idx != nil {
		return idx
	}
	return &hostIndex{}
}

// BridgePrefixOf returns the bridge network of an instance.
func BridgePrefixOf(inst *store.Instance) netip.Prefix {
	if p, err := netip.ParsePrefix(inst.BridgePrefix); err == nil {
		return p.Masked()
	}
	return netip.MustParsePrefix(store.DefaultBridgePrefix)
}

var (
	benchmarkRange = netip.MustParsePrefix("198.18.0.0/15")
)

// ValidBridgePrefix checks the bridge network of an instance: a private or
// benchmark IPv4 network (/16–/29) that cannot collide with tailnet
// addresses.
func ValidBridgePrefix(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil || !p.Addr().Is4() {
		return netip.Prefix{}, Errf("Brücken-Netz: bitte ein IPv4-Netz angeben, z. B. 198.18.0.0/24")
	}
	p = p.Masked()
	if p.Bits() < 16 || p.Bits() > 29 {
		return netip.Prefix{}, Errf("Brücken-Netz: Größe /16 bis /29")
	}
	if p.Overlaps(cgnat) {
		return netip.Prefix{}, Errf("Brücken-Netz darf nicht im Tailnet-Bereich 100.64.0.0/10 liegen")
	}
	if !p.Addr().IsPrivate() && !benchmarkRange.Contains(p.Addr()) {
		return netip.Prefix{}, Errf("Brücken-Netz: nur private Netze (10/8, 172.16/12, 192.168/16) oder 198.18.0.0/15")
	}
	return p, nil
}

// allocVirtualIP picks the lowest free host address of the bridge network.
func allocVirtualIP(p netip.Prefix, used map[netip.Addr]bool) (netip.Addr, error) {
	last := netip.Addr{}
	for a := p.Addr().Next(); p.Contains(a); a = a.Next() {
		last = a
	}
	for a := p.Addr().Next(); p.Contains(a) && a != last; a = a.Next() { // skip network and broadcast
		if !used[a] {
			return a, nil
		}
	}
	return netip.Addr{}, Errf("Im Brücken-Netz %s ist keine Adresse mehr frei", p)
}

// dnsLabel turns a device name into a DNS label.
func dnsLabel(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_' || r == ' ' || r == '.':
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 63 {
		out = strings.Trim(out[:63], "-")
	}
	return out
}

// bridgeHost returns the address of the bridged device in the source
// tailnet.
func (a *App) bridgeHost(b *store.Bridge) (string, error) {
	if b.NodeID == 0 {
		addr, err := netip.ParseAddr(b.TargetHost)
		if err != nil {
			return "", fmt.Errorf("invalid target %q", b.TargetHost)
		}
		from, err := a.DB.GetInstance(context.Background(), b.FromInstanceID)
		if err != nil {
			return "", err
		}
		if !a.targetAllowed(from, addr.Unmap()) {
			return "", fmt.Errorf("target %s is not inside the source tailnet or an approved subnet", addr)
		}
		return addr.Unmap().String(), nil
	}
	n := a.findNode(b.FromInstanceID, b.NodeID)
	switch {
	case n == nil:
		return "", fmt.Errorf("source node %d not found", b.NodeID)
	case n.ipv4 != "":
		return n.ipv4, nil
	case n.ipv6 != "":
		return n.ipv6, nil
	}
	return "", fmt.Errorf("source node %d has no address", b.NodeID)
}

// bridgeInterceptor serves the virtual addresses of one instance.
type bridgeInterceptor struct {
	a    *App
	inst int64
}

// lookup returns the bridge for a flow; ok=false when the destination is
// not inside the bridge network (the flow is not ours).
func (bi bridgeInterceptor) lookup(src, dst netip.AddrPort) (b *store.Bridge, ok bool) {
	idx := bi.a.hostIdx()
	p, has := idx.prefix[bi.inst]
	if !has || !p.Contains(dst.Addr().Unmap()) {
		return nil, false
	}
	b = idx.hosts[bi.inst][dst.Addr().Unmap()]
	if b == nil || !bi.a.bridgeAdmits(b, src.Addr()) {
		return nil, true // inside the bridge network but not allowed: reject
	}
	return b, true
}

func (bi bridgeInterceptor) TCP(src, dst netip.AddrPort) (func(net.Conn), bool) {
	b, ok := bi.lookup(src, dst)
	if !ok || b == nil {
		return nil, ok
	}
	return func(c net.Conn) { bi.a.relayHostTCP(b, c, dst.Port()) }, true
}

func (bi bridgeInterceptor) UDP(src, dst netip.AddrPort) (func(nettype.ConnPacketConn), bool) {
	b, ok := bi.lookup(src, dst)
	if !ok || b == nil {
		return nil, ok
	}
	return func(c nettype.ConnPacketConn) { bi.a.relayHostUDP(b, c, dst.Port()) }, true
}

var _ gateway.Interceptor = bridgeInterceptor{}

func (a *App) relayHostTCP(b *store.Bridge, client net.Conn, port uint16) {
	defer client.Close()
	c := a.BridgeReg.Get(b.ID)
	c.Active.Add(1)
	c.Total.Add(1)
	defer c.Active.Add(-1)
	host, err := a.bridgeHost(b)
	if err != nil {
		c.RecordError(err)
		return
	}
	ctx, cancel := context.WithTimeout(a.ctx, 15*time.Second)
	up, err := a.GW.Dial(ctx, b.FromInstanceID, "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	cancel()
	if err != nil {
		c.RecordError(fmt.Errorf("dial %s:%d: %w", host, port, err))
		return
	}
	defer up.Close()
	forward.Pipe(a.ctx, client, up, c)
}

const hostUDPIdle = 2 * time.Minute

func (a *App) relayHostUDP(b *store.Bridge, client nettype.ConnPacketConn, port uint16) {
	defer client.Close()
	c := a.BridgeReg.Get(b.ID)
	c.Active.Add(1)
	c.Total.Add(1)
	defer c.Active.Add(-1)
	host, err := a.bridgeHost(b)
	if err != nil {
		c.RecordError(err)
		return
	}
	ctx, cancel := context.WithTimeout(a.ctx, 10*time.Second)
	up, err := a.GW.Dial(ctx, b.FromInstanceID, "udp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	cancel()
	if err != nil {
		c.RecordError(fmt.Errorf("dial udp %s:%d: %w", host, port, err))
		return
	}
	defer up.Close()
	done := make(chan struct{}, 2)
	copyDatagrams := func(dst, src net.Conn, n *int64Adder) {
		buf := make([]byte, 65535)
		for {
			src.SetReadDeadline(time.Now().Add(hostUDPIdle))
			k, err := src.Read(buf)
			if err != nil {
				break
			}
			if _, err := dst.Write(buf[:k]); err != nil {
				break
			}
			n.add(int64(k))
		}
		done <- struct{}{}
	}
	go copyDatagrams(up, client, &int64Adder{f: c.BytesIn.Add})
	go copyDatagrams(client, up, &int64Adder{f: c.BytesOut.Add})
	<-done
}

type int64Adder struct{ f func(int64) int64 }

func (a *int64Adder) add(n int64) { a.f(n) }

// syncHostBridges updates the in-memory index, the advertised bridge
// networks and the DNS names after a change.
func (a *App) syncHostBridges(ctx context.Context, bridges []*store.Bridge, insts []*store.Instance) {
	idx := &hostIndex{prefix: map[int64]netip.Prefix{}, hosts: map[int64]map[netip.Addr]*store.Bridge{}}
	enabled := map[int64]bool{}
	for _, i := range insts {
		idx.prefix[i.ID] = BridgePrefixOf(i)
		enabled[i.ID] = i.Enabled
	}
	for _, b := range bridges {
		if !b.IsHost() || !b.Enabled || !enabled[b.FromInstanceID] || !enabled[b.ToInstanceID] {
			continue
		}
		vip, err := netip.ParseAddr(b.VirtualIP)
		if err != nil {
			continue
		}
		bc := *b
		if idx.hosts[b.ToInstanceID] == nil {
			idx.hosts[b.ToInstanceID] = map[netip.Addr]*store.Bridge{}
		}
		idx.hosts[b.ToInstanceID][vip] = &bc
	}
	a.hostBridges.Store(idx)
	for _, i := range insts {
		var routes []netip.Prefix
		if len(idx.hosts[i.ID]) > 0 {
			routes = []netip.Prefix{idx.prefix[i.ID]}
		}
		a.GW.SetRoutes(i.ID, routes)
		if err := a.writeExtraRecords(i, idx.hosts[i.ID]); err != nil {
			a.Log.Warn("writing DNS records failed", "instance", i.Slug, "err", err)
		}
	}
}

// wantsBridgeRoute reports whether the instance's server node must offer
// its bridge network (at least one active host bridge into it).
func (a *App) wantsBridgeRoute(inst *store.Instance) (netip.Prefix, bool) {
	idx := a.hostIdx()
	return BridgePrefixOf(inst), len(idx.hosts[inst.ID]) > 0
}

type extraRecord struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// writeExtraRecords publishes the DNS names of host bridges via headscale's
// extra records file (headscale reloads it on change).
func (a *App) writeExtraRecords(inst *store.Instance, hosts map[netip.Addr]*store.Bridge) error {
	recs := []extraRecord{}
	if inst.MagicDNS && inst.BaseDomain != "" {
		for vip, b := range hosts {
			if b.DNSName != "" {
				recs = append(recs, extraRecord{Name: b.DNSName + "." + inst.BaseDomain, Type: "A", Value: vip.String()})
			}
		}
	}
	sortRecords(recs)
	data, _ := json.MarshalIndent(recs, "", "  ")
	dir := a.InstanceDir(inst.Slug)
	path := filepath.Join(dir, extraRecordsFile)
	if cur, err := os.ReadFile(path); err == nil && bytes.Equal(cur, data) {
		return nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o640) // in place: headscale watches the file
}

func sortRecords(r []extraRecord) {
	for i := 1; i < len(r); i++ {
		for j := i; j > 0 && r[j].Name < r[j-1].Name; j-- {
			r[j], r[j-1] = r[j-1], r[j]
		}
	}
}

// extraRecordsFile is relative to the instance directory (see headscale
// config).
const extraRecordsFile = "extra-records.json"

// BridgeDNS returns the full DNS name of a host bridge ("" = none).
func BridgeDNS(b *store.Bridge, to *store.Instance) string {
	if !b.IsHost() || b.DNSName == "" || !to.MagicDNS || to.BaseDomain == "" {
		return ""
	}
	return b.DNSName + "." + to.BaseDomain
}
