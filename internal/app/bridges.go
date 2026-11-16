package app

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/testbild-media/openHeadscaleGUI/internal/forward"
	"github.com/testbild-media/openHeadscaleGUI/internal/store"
)

// A bridge publishes one service of a device in instance "from" into
// instance "to": the server's gateway listens on its address there (.1)
// and relays connections of the selected clients through the gateway of
// the source instance. The tailnets themselves stay separate.

// BridgeRequest is the editable part of a bridge.
type BridgeRequest struct {
	Name           string
	Mode           string // store.BridgeHost or store.BridgePort
	DNSName        string // host bridges: optional DNS label
	VirtualIP      string // host bridges: set by validation
	FromInstanceID int64
	NodeID         int64
	TargetHost     string
	TargetPort     int
	Proto          string
	ToInstanceID   int64
	ListenPort     int
	AllowAll       bool
	AllowedNodes   []int64
	Enabled        bool
}

// BridgeRequestFrom converts a bridge into editable values.
func BridgeRequestFrom(b *store.Bridge) BridgeRequest {
	return BridgeRequest{Name: b.Name, Mode: b.Mode, DNSName: b.DNSName, VirtualIP: b.VirtualIP, FromInstanceID: b.FromInstanceID, NodeID: b.NodeID, TargetHost: b.TargetHost,
		TargetPort: b.TargetPort, Proto: b.Proto, ToInstanceID: b.ToInstanceID, ListenPort: b.ListenPort,
		AllowAll: b.AllowAll, AllowedNodes: b.AllowedNodes, Enabled: b.Enabled}
}

// bridgeInstances loads both ends; the actor must manage both.
func (a *App) bridgeInstances(ctx context.Context, actor Actor, fromID, toID int64) (*store.Instance, *store.Instance, error) {
	from, err := a.DB.GetInstance(ctx, fromID)
	if err != nil {
		return nil, nil, Errf("Bitte die Instanz mit dem Server wählen")
	}
	to, err := a.DB.GetInstance(ctx, toID)
	if err != nil {
		return nil, nil, Errf("Bitte die Instanz mit den Clients wählen")
	}
	if !CanManage(actor.User, from) || !CanManage(actor.User, to) {
		return nil, nil, ErrForbidden
	}
	return from, to, nil
}

// CanManageBridge reports whether the actor manages both ends of b.
func (a *App) CanManageBridge(ctx context.Context, actor Actor, b *store.Bridge) bool {
	_, _, err := a.bridgeInstances(ctx, actor, b.FromInstanceID, b.ToInstanceID)
	return err == nil
}

func (a *App) validateBridge(ctx context.Context, actor Actor, r *BridgeRequest, exceptID int64) error {
	from, to, err := a.bridgeInstances(ctx, actor, r.FromInstanceID, r.ToInstanceID)
	if err != nil {
		return err
	}
	if from.ID == to.ID {
		return Errf("Server und Clients müssen in verschiedenen Instanzen liegen – innerhalb einer Instanz erreichen sich die Geräte direkt")
	}
	if r.Mode == "" {
		r.Mode = store.BridgeHost
	}
	host := r.Mode == store.BridgeHost
	if !host && r.Mode != store.BridgePort {
		return Errf("Ungültige Art der Brücke")
	}
	if host {
		r.Proto, r.TargetPort, r.ListenPort = "tcp", 0, 0
	} else {
		r.VirtualIP, r.DNSName = "", ""
		if r.Proto != "tcp" && r.Proto != "udp" {
			return Errf("Bitte TCP oder UDP wählen")
		}
		if err := ValidPort(r.TargetPort); err != nil {
			return err
		}
		if err := ValidPort(r.ListenPort); err != nil {
			return Errf("Port in der Client-Instanz: %v", err)
		}
	}
	srcName := ""
	r.TargetHost = strings.TrimSpace(r.TargetHost)
	if r.NodeID != 0 {
		n := a.findNode(from.ID, r.NodeID)
		if n == nil || a.isGateway(from, uint64(r.NodeID)) {
			return Errf("Das Gerät existiert in der Server-Instanz nicht")
		}
		r.TargetHost, srcName = "", n.DisplayName()
	} else {
		addr, err := netip.ParseAddr(r.TargetHost)
		if err != nil {
			return Errf("Bitte ein Gerät oder eine IP-Adresse in der Server-Instanz angeben")
		}
		addr = addr.Unmap()
		if !a.targetAllowed(from, addr) {
			return Errf("%s liegt weder im Tailnet der Server-Instanz noch in einem dort freigegebenen Subnetz", addr)
		}
		r.TargetHost, srcName = addr.String(), addr.String()
	}
	bridges, _ := a.DB.ListBridges(ctx)
	usedIPs := map[netip.Addr]bool{}
	labels := map[string]bool{}
	for _, n := range a.CachedNodes(to.ID) {
		labels[strings.ToLower(n.GivenName)] = true
	}
	for _, b := range bridges {
		if b.ID == exceptID || b.ToInstanceID != to.ID {
			continue
		}
		if !host && !b.IsHost() && b.Proto == r.Proto && b.ListenPort == r.ListenPort {
			return Errf("Port %s/%d ist in %s bereits durch „%s“ belegt", r.Proto, r.ListenPort, to.Name, b.Name)
		}
		if host && b.IsHost() {
			if b.FromInstanceID == from.ID && b.NodeID == r.NodeID && b.TargetHost == r.TargetHost {
				return Errf("Dieses Gerät ist in %s bereits über „%s“ erreichbar – dort weitere Geräte erlauben", to.Name, b.Name)
			}
			if ip, err := netip.ParseAddr(b.VirtualIP); err == nil {
				usedIPs[ip] = true
			}
			if b.DNSName != "" {
				labels[b.DNSName] = true
			}
		}
	}
	if host {
		prefix := BridgePrefixOf(to)
		if ip, err := netip.ParseAddr(r.VirtualIP); err != nil || !prefix.Contains(ip) || usedIPs[ip] {
			vip, err := allocVirtualIP(prefix, usedIPs)
			if err != nil {
				return err
			}
			r.VirtualIP = vip.String()
		}
		label := dnsLabel(r.DNSName)
		if r.DNSName != "" && label == "" {
			return Errf("Ungültiger DNS-Name")
		}
		if label == "" {
			label = dnsLabel(srcName)
		}
		if label != "" && labels[label] {
			if r.DNSName != "" {
				return Errf("Der DNS-Name „%s“ ist in %s bereits vergeben", label, to.Name)
			}
			label = dnsLabel(label + "-bridge")
			if labels[label] {
				label = ""
			}
		}
		if net.ParseIP(srcName) != nil && r.DNSName == "" {
			label = "" // no automatic name for plain IP sources
		}
		r.DNSName = label
	}
	var allowed []int64
	for _, id := range r.AllowedNodes {
		if id == 0 || slices.Contains(allowed, id) {
			continue
		}
		if a.findNode(to.ID, id) == nil || a.isGateway(to, uint64(id)) {
			return Errf("Ein ausgewähltes Gerät existiert in %s nicht", to.Name)
		}
		allowed = append(allowed, id)
	}
	slices.Sort(allowed)
	if r.AllowAll {
		allowed = nil
	} else if len(allowed) == 0 {
		return Errf("Bitte mindestens ein Gerät auswählen, das den Dienst nutzen darf (oder alle Geräte erlauben)")
	}
	r.AllowedNodes = allowed
	r.Name = strings.TrimSpace(r.Name)
	if r.Name == "" && host {
		r.Name = srcName
	} else if r.Name == "" {
		r.Name = fmt.Sprintf("%s:%d", srcName, r.TargetPort)
	}
	if len([]rune(r.Name)) > 80 {
		return Errf("Name: höchstens 80 Zeichen")
	}
	return nil
}

func (a *App) findNode(instanceID, nodeID int64) *nodeRef {
	for _, n := range a.CachedNodes(instanceID) {
		if int64(n.ID) == nodeID {
			return &nodeRef{name: n.DisplayName(), ipv4: n.IPv4(), ipv6: n.IPv6()}
		}
	}
	return nil
}

type nodeRef struct{ name, ipv4, ipv6 string }

func (n *nodeRef) DisplayName() string { return n.name }

func fillBridge(b *store.Bridge, r BridgeRequest) {
	b.Mode, b.VirtualIP, b.DNSName = r.Mode, r.VirtualIP, r.DNSName
	b.Name, b.FromInstanceID, b.NodeID, b.TargetHost, b.TargetPort = r.Name, r.FromInstanceID, r.NodeID, r.TargetHost, r.TargetPort
	b.Proto, b.ToInstanceID, b.ListenPort, b.AllowAll, b.AllowedNodes, b.Enabled = r.Proto, r.ToInstanceID, r.ListenPort, r.AllowAll, r.AllowedNodes, r.Enabled
}

func describeBridge(b *store.Bridge) string {
	if b.IsHost() {
		return fmt.Sprintf("%s: inst#%d %s → inst#%d %s (alle Ports)", b.Name, b.FromInstanceID,
			map[bool]string{true: "node#" + strconv.FormatInt(b.NodeID, 10), false: b.TargetHost}[b.NodeID != 0],
			b.ToInstanceID, b.VirtualIP)
	}
	return fmt.Sprintf("%s: inst#%d %s → inst#%d .1:%d/%s", b.Name, b.FromInstanceID,
		map[bool]string{true: "node#" + strconv.FormatInt(b.NodeID, 10), false: b.TargetHost}[b.NodeID != 0],
		b.ToInstanceID, b.ListenPort, b.Proto)
}

// CreateBridge adds a bridge.
func (a *App) CreateBridge(ctx context.Context, actor Actor, r BridgeRequest) (*store.Bridge, error) {
	if err := a.validateBridge(ctx, actor, &r, 0); err != nil {
		return nil, err
	}
	b := &store.Bridge{}
	fillBridge(b, r)
	if err := a.DB.CreateBridge(ctx, b); err != nil {
		return nil, err
	}
	a.SyncBridges(ctx)
	a.Audit(ctx, actor, b.ToInstanceID, "bridge.create", describeBridge(b))
	return b, nil
}

// UpdateBridge changes a bridge.
func (a *App) UpdateBridge(ctx context.Context, actor Actor, b *store.Bridge, r BridgeRequest) error {
	if !a.CanManageBridge(ctx, actor, b) {
		return ErrForbidden
	}
	if err := a.validateBridge(ctx, actor, &r, b.ID); err != nil {
		return err
	}
	fillBridge(b, r)
	if err := a.DB.UpdateBridge(ctx, b); err != nil {
		return err
	}
	a.SyncBridges(ctx)
	a.Audit(ctx, actor, b.ToInstanceID, "bridge.update", describeBridge(b))
	return nil
}

// SetBridgeEnabled toggles a bridge.
func (a *App) SetBridgeEnabled(ctx context.Context, actor Actor, b *store.Bridge, on bool) error {
	if !a.CanManageBridge(ctx, actor, b) {
		return ErrForbidden
	}
	b.Enabled = on
	if err := a.DB.UpdateBridge(ctx, b); err != nil {
		return err
	}
	a.SyncBridges(ctx)
	a.Audit(ctx, actor, b.ToInstanceID, map[bool]string{true: "bridge.enable", false: "bridge.disable"}[on], describeBridge(b))
	return nil
}

// DeleteBridge removes a bridge.
func (a *App) DeleteBridge(ctx context.Context, actor Actor, b *store.Bridge) error {
	if !a.CanManageBridge(ctx, actor, b) {
		return ErrForbidden
	}
	if err := a.DB.DeleteBridge(ctx, b.ID); err != nil {
		return err
	}
	a.SyncBridges(ctx)
	a.Audit(ctx, actor, b.ToInstanceID, "bridge.delete", describeBridge(b))
	return nil
}

// BridgeTarget resolves the current address of the bridged service inside
// the source tailnet.
func (a *App) BridgeTarget(b *store.Bridge) (string, error) {
	if b.IsHost() {
		return a.bridgeHost(b)
	}
	port := strconv.Itoa(b.TargetPort)
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
		return net.JoinHostPort(addr.Unmap().String(), port), nil
	}
	n := a.findNode(b.FromInstanceID, b.NodeID)
	switch {
	case n == nil:
		return "", fmt.Errorf("source node %d not found", b.NodeID)
	case n.ipv4 != "":
		return net.JoinHostPort(n.ipv4, port), nil
	case n.ipv6 != "":
		return net.JoinHostPort(n.ipv6, port), nil
	}
	return "", fmt.Errorf("source node %d has no address", b.NodeID)
}

// bridgeClient returns the node of the target instance that owns ip.
func (a *App) bridgeClient(toInstanceID int64, ip netip.Addr) (int64, bool) {
	s := ip.Unmap().String()
	for _, n := range a.CachedNodes(toInstanceID) {
		if n.IPv4() == s || n.IPv6() == s {
			return int64(n.ID), true
		}
	}
	return 0, false
}

// bridgeAdmits decides per connection (and per UDP packet), in memory: b is
// the bridge as of the last sync (every change restarts its listener) and
// node addresses come from the node cache.
func (a *App) bridgeAdmits(b *store.Bridge, ip netip.Addr) bool {
	node, ok := a.bridgeClient(b.ToInstanceID, ip)
	if !ok || uint64(node) == a.GatewayNodeID(b.ToInstanceID) {
		return false
	}
	return b.Allows(node)
}

// BridgeScope keys the listeners of one target instance.
func BridgeScope(toInstanceID int64) string { return "i" + strconv.FormatInt(toInstanceID, 10) + "/" }

// BridgeRule returns the relay rule of a bridge (used for status queries).
func BridgeRule(b *store.Bridge) forward.Rule {
	return forward.Rule{ID: b.ID, Proto: b.Proto, Port: b.ListenPort, Scope: BridgeScope(b.ToInstanceID)}
}

// SyncBridges makes the bridge listeners match the database.
func (a *App) SyncBridges(ctx context.Context) {
	if a.Bridges == nil {
		return
	}
	bridges, err := a.DB.ListBridges(ctx)
	if err != nil {
		return
	}
	insts, _ := a.DB.ListInstances(ctx, 0)
	enabled := map[int64]bool{}
	for _, i := range insts {
		enabled[i.ID] = i.Enabled
	}
	a.syncHostBridges(ctx, bridges, insts)
	var rules []forward.Rule
	for _, b := range bridges {
		if b.IsHost() || !b.Enabled || !enabled[b.FromInstanceID] || !enabled[b.ToInstanceID] {
			continue
		}
		bc := *b
		rule := BridgeRule(&bc)
		rule.InstanceID = bc.FromInstanceID
		rule.Version = bc.UpdatedAt
		rule.Target = func() (string, error) { return a.BridgeTarget(&bc) }
		rule.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return a.GW.Dial(ctx, bc.FromInstanceID, network, addr)
		}
		rule.ListenTCP = func() (net.Listener, error) { return a.GW.Listen(bc.ToInstanceID, bc.ListenPort) }
		rule.ListenUDP = func() (net.PacketConn, error) { return a.GW.ListenPacket(bc.ToInstanceID, bc.ListenPort) }
		rule.Admit = func(ip netip.Addr) bool { return a.bridgeAdmits(&bc, ip) }
		rules = append(rules, rule)
	}
	a.Bridges.Sync(rules)
}
