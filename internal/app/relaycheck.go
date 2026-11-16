package app

import (
	"context"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/testbild-media/openHeadscaleGUI/internal/derp"
	"github.com/testbild-media/openHeadscaleGUI/internal/store"
)

// relayOnlyCentral reports whether the central DERP is the only relay of
// the devices of an instance. Only then must every online device hold a
// connection to it; with the public relays it may have its home elsewhere.
func relayOnlyCentral(inst *store.Instance, derpRunning bool) bool {
	return derpRunning && inst.Enabled && inst.UseCentralDERP && !inst.UsePublicDERP
}

func (s monitorSource) RelayExpected(id int64) bool {
	if s.a.DERP == nil || !s.a.DERP.Stats().Running {
		return false
	}
	inst, err := s.a.DB.GetInstance(s.a.ctx, id)
	if err != nil {
		return false
	}
	return relayOnlyCentral(inst, true)
}

// udpCheckAfter is how long the STUN server must run before ohg judges
// whether UDP from the internet arrives. Devices ask it right after
// connecting to the relay (also after every restart of ohg), so a few
// minutes are plenty.
const udpCheckAfter = 5 * time.Minute

// UDPCheck is ohg's conclusion whether UDP from the internet reaches the
// server, judged by the STUN requests of the devices that use the relay.
type UDPCheck struct {
	// Known is set when there is enough data: STUN runs long enough and
	// devices from outside use the relay.
	Known bool
	// Blocked4/6: devices use the relay over IPv4/IPv6, but not a single
	// STUN request arrived over that family since Since.
	Blocked4, Blocked6 bool
	// Clients4/6 count the relay connections from outside per family.
	Clients4, Clients6 int
	Since              time.Time
	// LastExternal4/6 is the time of the last STUN request from outside.
	LastExternal4, LastExternal6 time.Time
	STUNPort                     int
	// GatewayPorts lists the UDP ports of the server nodes, e.g.
	// "41641–41642".
	GatewayPorts string
}

// Blocked reports whether any address family seems blocked.
func (c UDPCheck) Blocked() bool { return c.Blocked4 || c.Blocked6 }

// Families names the blocked address families ("IPv4", "IPv6" or both).
func (c UDPCheck) Families() string {
	var f []string
	if c.Blocked4 {
		f = append(f, "IPv4")
	}
	if c.Blocked6 {
		f = append(f, "IPv6")
	}
	return strings.Join(f, " und ")
}

// BlockedClients counts the relay clients of the blocked families.
func (c UDPCheck) BlockedClients() int {
	n := 0
	if c.Blocked4 {
		n += c.Clients4
	}
	if c.Blocked6 {
		n += c.Clients6
	}
	return n
}

func udpCheck(st derp.Stats, clients []derp.Client, isLocal func(netip.Addr) bool, now time.Time) UDPCheck {
	c := UDPCheck{Since: st.STUNSince, LastExternal4: st.STUNLastExternal4, LastExternal6: st.STUNLastExternal6}
	if !st.Running || !st.STUNRunning || st.STUNSince.IsZero() {
		return c
	}
	for _, cl := range clients {
		ap, err := netip.ParseAddrPort(cl.Remote)
		if err != nil {
			continue
		}
		ip := ap.Addr().Unmap()
		if isLocal(ip) {
			continue // the server's own nodes
		}
		if ip.Is4() {
			c.Clients4++
		} else {
			c.Clients6++
		}
	}
	if now.Sub(st.STUNSince) < udpCheckAfter || c.Clients4+c.Clients6 == 0 {
		return c
	}
	c.Known = true
	c.Blocked4 = c.Clients4 > 0 && st.STUNExternal4 == 0
	c.Blocked6 = c.Clients6 > 0 && st.STUNExternal6 == 0
	return c
}

// UDPCheck evaluates whether UDP from the internet reaches the server.
func (a *App) UDPCheck(ctx context.Context) UDPCheck {
	ds := a.DERPSettings(ctx)
	if !ds.Enabled || a.DERP == nil {
		return UDPCheck{}
	}
	clients, _ := a.DERP.Clients(5000)
	c := udpCheck(a.DERP.Stats(), clients, a.DERP.IsLocal, time.Now())
	c.STUNPort = ds.STUNPort
	insts, _ := a.DB.ListInstances(ctx, 0)
	var ports []int
	for _, i := range insts {
		if i.Enabled && i.GatewayPort > 0 {
			ports = append(ports, i.GatewayPort)
		}
	}
	c.GatewayPorts = portList(ports)
	return c
}

// portList formats ports compactly: "41641", "41641–41643" or
// "41641, 41650".
func portList(ports []int) string {
	if len(ports) == 0 {
		return ""
	}
	p := slices.Clone(ports)
	slices.Sort(p)
	p = slices.Compact(p)
	if len(p) > 1 && p[len(p)-1]-p[0] == len(p)-1 {
		return strconv.Itoa(p[0]) + "–" + strconv.Itoa(p[len(p)-1])
	}
	s := make([]string, len(p))
	for i, v := range p {
		s[i] = strconv.Itoa(v)
	}
	return strings.Join(s, ", ")
}

// RelayIssue is an online device that has not been connected to the
// central relay for a while (see monitor.RelayGrace).
type RelayIssue struct {
	InstanceID int64
	Instance   string
	NodeID     uint64
	Node       string
	Since      time.Time
}

// RelayIssues lists the devices without relay connection that the user
// may see.
func (a *App) RelayIssues(ctx context.Context, u *store.User) []RelayIssue {
	issues := a.Mon.RelayIssues()
	if len(issues) == 0 {
		return nil
	}
	insts, _ := a.DB.ListInstances(ctx, 0)
	byID := map[int64]*store.Instance{}
	for _, i := range insts {
		byID[i.ID] = i
	}
	var out []RelayIssue
	for _, is := range issues {
		inst := byID[is.InstanceID]
		if inst == nil || !CanManage(u, inst) {
			continue
		}
		name := "#" + strconv.FormatUint(is.NodeID, 10)
		for _, n := range a.CachedNodes(inst.ID) {
			if uint64(n.ID) == is.NodeID {
				name = n.DisplayName()
			}
		}
		out = append(out, RelayIssue{InstanceID: inst.ID, Instance: inst.Name, NodeID: is.NodeID, Node: name, Since: is.Since})
	}
	return out
}
