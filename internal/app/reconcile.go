package app

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"time"

	"github.com/testbild-media/openHeadscaleGUI/internal/gateway"
	"github.com/testbild-media/openHeadscaleGUI/internal/headscale"
	"github.com/testbild-media/openHeadscaleGUI/internal/store"
)

// Trigger schedules an immediate reconcile run for an instance.
func (a *App) Trigger(id int64) {
	select {
	case a.reconCh <- id:
	default:
	}
}

func (a *App) reconcileLoop() {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-a.ctx.Done():
			return
		case id := <-a.reconCh:
			if inst, err := a.DB.GetInstance(a.ctx, id); err == nil {
				a.reconcile(inst)
			}
			a.rebuildDERPIndex()
		case <-t.C:
			insts, err := a.DB.ListInstances(a.ctx, 0)
			if err != nil {
				continue
			}
			for _, inst := range insts {
				if inst.Enabled {
					a.reconcile(inst)
				}
			}
			a.rebuildDERPIndex()
		}
	}
}

var exitRoutes = []string{"0.0.0.0/0", "::/0"}

func isExitRoute(r string) bool { return r == "0.0.0.0/0" || r == "::/0" }

// reconcile brings one instance to its desired state.
func (a *App) reconcile(inst *store.Instance) {
	if !inst.Enabled || a.HS.Status(inst.ID).State != headscale.StateRunning {
		return
	}
	l := a.opLock(inst.ID)
	if !l.TryLock() {
		return // another operation (e.g. IP change) is running
	}
	defer l.Unlock()
	ctx, cancel := context.WithTimeout(a.ctx, time.Minute)
	defer cancel()
	log := a.Log.With("instance", inst.Slug, "component", "reconcile")
	nodes, err := a.refreshNodes(ctx, inst)
	if err != nil {
		log.Debug("listing nodes failed", "err", err)
		return
	}
	c, err := a.Client(ctx, inst)
	if err != nil {
		return
	}
	byID := map[uint64]*headscale.Node{}
	byIPv4 := map[string]*headscale.Node{}
	byIPv6 := map[string]*headscale.Node{}
	for i := range nodes {
		n := &nodes[i]
		byID[uint64(n.ID)] = n
		if ip := n.IPv4(); ip != "" {
			byIPv4[ip] = n
		}
		if ip := n.IPv6(); ip != "" {
			byIPv6[ip] = n
		}
	}
	var changes []headscale.IPChange
	changed := false

	// ---- gateway: reserved .1, exit node approval ----
	gwID := a.GatewayNodeID(inst.ID)
	if gw := byID[gwID]; gw != nil {
		want4 := ReservedIPv4(inst).String()
		want6 := ReservedIPv6(inst).String()
		ch := headscale.IPChange{NodeID: gwID}
		if gw.IPv4() != want4 {
			ch.IPv4 = want4
			if other := byIPv4[want4]; other != nil && uint64(other.ID) != gwID {
				// swap: give the occupant the gateway's current address
				if free := gw.IPv4(); free != "" {
					changes = append(changes, headscale.IPChange{NodeID: uint64(other.ID), IPv4: free})
				} else if free, ok := a.freeIPv4(inst, byIPv4); ok {
					changes = append(changes, headscale.IPChange{NodeID: uint64(other.ID), IPv4: free})
				}
			}
		}
		if gw.IPv6() != want6 && want6 != "" {
			ch.IPv6 = want6
			if other := byIPv6[want6]; other != nil && uint64(other.ID) != gwID {
				if free := gw.IPv6(); free != "" {
					changes = append(changes, headscale.IPChange{NodeID: uint64(other.ID), IPv6: free})
				}
			}
		}
		if ch.IPv4 != "" || ch.IPv6 != "" {
			log.Info("moving gateway to reserved address", "ipv4", want4)
			changes = append(changes, ch)
		}
		// exit node approval
		approved := slices.Clone(gw.ApprovedRoutes)
		desired := []string{}
		for _, r := range approved {
			if !isExitRoute(r) {
				desired = append(desired, r)
			}
		}
		if inst.GatewayExitNode {
			for _, r := range exitRoutes {
				if slices.Contains(gw.AvailableRoutes, r) {
					desired = append(desired, r)
				}
			}
		}
		if !sameSet(approved, desired) {
			if err := c.SetApprovedRoutes(ctx, gwID, desired); err != nil {
				log.Warn("updating gateway exit routes failed", "err", err)
			} else {
				changed = true
			}
		}
		// remove stale system nodes (old gateway registrations)
		for _, n := range nodes {
			if uint64(n.ID) == gwID || n.UserName() != gateway.SystemUser || n.Online {
				continue
			}
			if n.LastSeen != nil && time.Since(*n.LastSeen) < 10*time.Minute {
				continue
			}
			log.Info("removing stale gateway registration", "node", n.ID)
			if err := c.DeleteNode(ctx, uint64(n.ID)); err == nil {
				changed = true
			}
		}
	}

	// ---- client profiles ----
	profiles, _ := a.DB.ListProfiles(ctx, inst.ID)
	byKey := map[uint64]*headscale.Node{}
	for i := range nodes {
		if nodes[i].PreAuthKey != nil {
			byKey[uint64(nodes[i].PreAuthKey.ID)] = &nodes[i]
		}
	}
	reserved := ReservedIPv4(inst).String()
	for _, p := range profiles {
		orig := *p
		var n *headscale.Node
		// A node registered with the profile's current key always wins; this
		// also rebinds the profile after a re-registration with a new key.
		if kn := byKey[uint64(p.PreAuthKeyID)]; p.PreAuthKeyID != 0 && kn != nil && int64(kn.ID) != p.NodeID {
			n = kn
			p.NodeID = int64(n.ID)
			p.Status = store.ProfileRegistered
			p.LastError = ""
			log.Info("client profile registered", "profile", p.Name, "node", n.ID)
		} else if p.NodeID != 0 {
			n = byID[uint64(p.NodeID)]
			if n == nil {
				p.NodeID, p.Status, p.LastError = 0, store.ProfileWaiting, "Gerät wurde entfernt – für eine neue Anmeldung „Neuer Schlüssel“ verwenden"
				_ = a.DB.UpdateProfile(ctx, p)
				continue
			}
		}
		if n == nil {
			continue
		}
		perr := ""
		if name, err := NodeName(p.Name); err == nil && n.GivenName != name {
			if err := c.RenameNode(ctx, uint64(n.ID), name); err != nil {
				perr = "Umbenennen fehlgeschlagen: " + err.Error()
			} else {
				changed = true
			}
		}
		if p.DesiredIPv4 != "" && n.IPv4() != p.DesiredIPv4 {
			if p.DesiredIPv4 == reserved {
				perr = "Die IP ist für den Server reserviert"
			} else if other := byIPv4[p.DesiredIPv4]; other != nil && other.ID != n.ID {
				perr = fmt.Sprintf("Die IP %s ist bereits durch %s belegt", p.DesiredIPv4, other.DisplayName())
			} else {
				changes = append(changes, headscale.IPChange{NodeID: uint64(n.ID), IPv4: p.DesiredIPv4})
			}
		}
		// auto approve routes advertised by the client
		auto := p.AutoRouteList()
		if p.AutoExit {
			auto = append(auto, exitRoutes...)
		}
		if len(auto) > 0 {
			desired := slices.Clone(n.ApprovedRoutes)
			for _, r := range n.AvailableRoutes {
				if slices.Contains(auto, r) && !slices.Contains(desired, r) {
					desired = append(desired, r)
				}
			}
			if !sameSet(desired, n.ApprovedRoutes) {
				if err := c.SetApprovedRoutes(ctx, uint64(n.ID), desired); err != nil {
					perr = "Routenfreigabe fehlgeschlagen: " + err.Error()
				} else {
					changed = true
				}
			}
		}
		status := store.ProfileApplied
		if perr != "" {
			status = store.ProfileError
		} else if p.DesiredIPv4 != "" && n.IPv4() != p.DesiredIPv4 {
			status = store.ProfileRegistered
		}
		p.Status, p.LastError = status, perr
		if p.Status != orig.Status || p.LastError != orig.LastError || p.NodeID != orig.NodeID {
			_ = a.DB.UpdateProfile(ctx, p)
		}
	}

	if len(changes) > 0 {
		if until, ok := a.ipFailUntil.Load(inst.ID); ok && time.Now().Before(until.(time.Time)) {
			return
		}
		if err := a.applyIPChangesLocked(ctx, inst, changes); err != nil {
			log.Error("applying IP changes failed", "err", err)
			a.ipFailUntil.Store(inst.ID, time.Now().Add(5*time.Minute))
		} else {
			a.ipFailUntil.Delete(inst.ID)
		}
		return
	}
	if changed {
		_, _ = a.refreshNodes(ctx, inst)
	}
}

func (a *App) freeIPv4(inst *store.Instance, used map[string]*headscale.Node) (string, bool) {
	p, err := netip.ParsePrefix(inst.PrefixV4)
	if err != nil {
		return "", false
	}
	ip := ReservedIPv4(inst).Next()
	for i := 0; i < 1<<16 && p.Contains(ip); i++ {
		if _, ok := used[ip.String()]; !ok && ip != quad100 && !chromeOSRange.Contains(ip) {
			return ip.String(), true
		}
		ip = ip.Next()
	}
	return "", false
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := slices.Clone(a), slices.Clone(b)
	sort.Strings(x)
	sort.Strings(y)
	return slices.Equal(x, y)
}

// applyIPChangesLocked stops headscale, rewrites node addresses and starts
// it again. The caller must hold the instance op lock.
func (a *App) applyIPChangesLocked(ctx context.Context, inst *store.Instance, changes []headscale.IPChange) error {
	a.Log.Info("applying IP changes (headscale restart)", "instance", inst.Slug, "changes", len(changes))
	a.HS.Stop(inst.ID)
	err := headscale.ApplyIPChanges(ctx, headscale.DBPath(a.InstanceDir(inst.Slug)), changes)
	if startErr := a.startInstance(inst); startErr != nil && err == nil {
		err = startErr
	}
	wctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if werr := a.HS.WaitReady(wctx, inst.ID); werr != nil && err == nil {
		err = werr
	}
	if err == nil {
		_, _ = a.refreshNodes(ctx, inst)
	}
	return err
}

// ---- DERP admission ----

func (a *App) rebuildDERPIndex() {
	idx := map[string]int64{}
	insts, err := a.DB.ListInstances(a.ctx, 0)
	if err != nil {
		return
	}
	for _, inst := range insts {
		if !inst.Enabled || !inst.UseCentralDERP {
			continue
		}
		for _, n := range a.CachedNodes(inst.ID) {
			if n.NodeKey != "" {
				idx[n.NodeKey] = inst.ID
			}
		}
		// the gateway itself may connect before it shows up in the list
		if k := a.GW.Status(inst.ID).NodeKey; k != "" {
			idx[k] = inst.ID
		}
	}
	a.derpIndex.Store(&idx)
}

// admitDERP is the DERP admission controller.
func (a *App) admitDERP(nodeKey string, src netip.Addr) bool {
	ctx, cancel := context.WithTimeout(a.ctx, 4*time.Second)
	defer cancel()
	keys, _ := a.DB.ListDERPKeys(ctx)
	for _, k := range keys {
		if k.NodeKey == nodeKey {
			return k.Mode == "allow"
		}
	}
	if _, ok := (*a.derpIndex.Load())[nodeKey]; ok {
		return true
	}
	// Unknown key: the node may have registered seconds ago. Refresh all
	// instances (rate limited) and check again.
	a.derpRefresh.Lock()
	if time.Since(a.derpLastFull) > 3*time.Second {
		a.derpLastFull = time.Now()
		insts, _ := a.DB.ListInstances(ctx, 0)
		for _, inst := range insts {
			if inst.Enabled && inst.UseCentralDERP {
				_, _ = a.refreshNodes(ctx, inst)
			}
		}
		a.rebuildDERPIndex()
	}
	a.derpRefresh.Unlock()
	_, ok := (*a.derpIndex.Load())[nodeKey]
	return ok
}
