package app

import (
	"context"
	"net/netip"
	"strconv"
	"strings"

	"github.com/testbild-media/openHeadscaleGUI/internal/derp"
	"github.com/testbild-media/openHeadscaleGUI/internal/store"
)

// DERPSettings returns the configured DERP settings.
func (a *App) DERPSettings(ctx context.Context) derp.Settings {
	return derp.Settings{
		Enabled:       a.DB.GetSettingBool(ctx, SetDERPEnabled, false),
		Domain:        a.DB.GetSetting(ctx, SetDERPDomain, ""),
		RegionID:      a.DB.GetSettingInt(ctx, SetDERPRegionID, 900),
		RegionCode:    a.DB.GetSetting(ctx, SetDERPRegionCode, "ohg"),
		RegionName:    a.DB.GetSetting(ctx, SetDERPRegionName, "OpenHeadscaleGUI DERP"),
		STUNPort:      a.DB.GetSettingInt(ctx, SetDERPSTUNPort, 3478),
		VerifyClients: a.DB.GetSettingBool(ctx, SetDERPVerify, true),
		FailOpen:      a.DB.GetSettingBool(ctx, SetDERPFailOpen, false),
		IPv4:          a.DB.GetSetting(ctx, SetDERPIPv4, a.Cfg.PublicIPv4),
		IPv6:          a.DB.GetSetting(ctx, SetDERPIPv6, a.Cfg.PublicIPv6),
	}
}

var regionCodeOK = func(s string) bool {
	if len(s) < 2 || len(s) > 16 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

// SaveDERPSettings validates, stores and applies the DERP settings. All
// instances using the central DERP get a new DERP map (and restart if it
// changed).
func (a *App) SaveDERPSettings(ctx context.Context, actor Actor, s derp.Settings) error {
	if !actor.User.IsSuperadmin() {
		return ErrForbidden
	}
	s.Domain = NormalizeDomain(s.Domain)
	if s.Enabled || s.Domain != "" {
		if err := ValidDomain(s.Domain); err != nil {
			return err
		}
		if used := a.domainInUse(ctx, s.Domain, 0, 0); used != "" && used != "DERP-Server" {
			return Errf("Die Domain wird bereits verwendet (%s)", used)
		}
	}
	if s.RegionID < 900 || s.RegionID > 999 {
		return Errf("Region-ID: 900–999 (eigene Regionen)")
	}
	s.RegionCode = strings.ToLower(strings.TrimSpace(s.RegionCode))
	if !regionCodeOK(s.RegionCode) {
		return Errf("Region-Code: 2–16 Zeichen a-z, 0-9, -")
	}
	s.RegionName = strings.TrimSpace(s.RegionName)
	if s.RegionName == "" || len(s.RegionName) > 64 {
		return Errf("Bitte einen Regionsnamen (max. 64 Zeichen) angeben")
	}
	if s.STUNPort != 0 && ValidPort(s.STUNPort) != nil {
		return Errf("Ungültiger STUN-Port")
	}
	s.IPv4, s.IPv6 = strings.ToLower(strings.TrimSpace(s.IPv4)), strings.ToLower(strings.TrimSpace(s.IPv6))
	if s.IPv4 != "" && s.IPv4 != DERPAddrNone {
		if ip, err := netip.ParseAddr(s.IPv4); err != nil || !ip.Is4() {
			return Errf("Ungültige IPv4-Adresse (leer = automatisch, none = kein IPv4)")
		}
	}
	if s.IPv6 != "" && s.IPv6 != DERPAddrNone {
		if ip, err := netip.ParseAddr(s.IPv6); err != nil || !ip.Is6() {
			return Errf("Ungültige IPv6-Adresse (leer = automatisch, none = kein IPv6)")
		}
	}
	b := func(v bool) string {
		if v {
			return "1"
		}
		return "0"
	}
	// capture old DERP maps
	insts, _ := a.DB.ListInstances(ctx, 0)
	oldMaps, oldCfgs := a.snapshotDERP(insts)
	if err := a.DB.SetSettings(ctx, map[string]string{
		SetDERPEnabled:    b(s.Enabled),
		SetDERPDomain:     s.Domain,
		SetDERPRegionID:   strconv.Itoa(s.RegionID),
		SetDERPRegionCode: s.RegionCode,
		SetDERPRegionName: s.RegionName,
		SetDERPSTUNPort:   strconv.Itoa(s.STUNPort),
		SetDERPVerify:     b(s.VerifyClients),
		SetDERPFailOpen:   b(s.FailOpen),
		SetDERPIPv4:       s.IPv4,
		SetDERPIPv6:       s.IPv6,
	}); err != nil {
		return err
	}
	if err := a.DERP.Apply(a.DERPSettings(ctx)); err != nil {
		return err
	}
	_ = a.RebuildRoutes(ctx)
	a.refreshDERPAddrs(ctx) // the domain may have changed
	a.restartChangedDERP(insts, oldMaps, oldCfgs)
	a.Audit(ctx, actor, 0, "derp.update", s.Domain)
	return nil
}

// SetDERPKey adds a manual allow/deny entry.
func (a *App) SetDERPKey(ctx context.Context, actor Actor, nodeKey, mode, note string) error {
	if !actor.User.IsSuperadmin() {
		return ErrForbidden
	}
	nodeKey = strings.TrimSpace(nodeKey)
	if !strings.HasPrefix(nodeKey, "nodekey:") || len(nodeKey) != len("nodekey:")+64 {
		return Errf("Ungültiger Node-Key (Format nodekey:<64 Hex-Zeichen>)")
	}
	if mode != "allow" && mode != "deny" {
		return Errf("Ungültiger Modus")
	}
	if err := a.DB.SetDERPKey(ctx, &store.DERPKey{NodeKey: nodeKey, Mode: mode, Note: strings.TrimSpace(note)}); err != nil {
		return err
	}
	a.Audit(ctx, actor, 0, "derp.key."+mode, nodeKey[:16])
	return nil
}

// DeleteDERPKey removes a manual entry.
func (a *App) DeleteDERPKey(ctx context.Context, actor Actor, nodeKey string) error {
	if !actor.User.IsSuperadmin() {
		return ErrForbidden
	}
	if err := a.DB.DeleteDERPKey(ctx, nodeKey); err != nil {
		return err
	}
	a.Audit(ctx, actor, 0, "derp.key.delete", nodeKey)
	return nil
}

// DERPClientInfo maps a DERP connection to an instance/node.
type DERPClientInfo struct {
	derp.Client
	Instance string
	Node     string
	Known    bool
}

// DERPClients lists relay connections with their owners.
func (a *App) DERPClients(ctx context.Context) []DERPClientInfo {
	clients, _ := a.DERP.Clients(2000)
	insts, _ := a.DB.ListInstances(ctx, 0)
	type owner struct{ inst, node string }
	byKey := map[string]owner{}
	for _, i := range insts {
		for _, n := range a.CachedNodes(i.ID) {
			byKey[n.NodeKey] = owner{i.Name, n.DisplayName()}
		}
	}
	out := make([]DERPClientInfo, 0, len(clients))
	for _, c := range clients {
		o, ok := byKey[c.Key]
		out = append(out, DERPClientInfo{Client: c, Instance: o.inst, Node: o.node, Known: ok})
	}
	return out
}

// DERPRejectedInfo is a rejected relay client with what ohg knows about it.
type DERPRejectedInfo struct {
	derp.Rejected
	Instance string
	Node     string
	// Reason explains why the key is not admitted.
	Reason string
}

// DERPRejected lists clients the relay turned away and tries to identify
// them: a device in an instance without the central DERP, in a disabled
// instance, on the denylist, or an unknown key (deleted device, old key
// after a re-registration, or a foreign client).
func (a *App) DERPRejected(ctx context.Context) []DERPRejectedInfo {
	rej := a.DERP.RecentRejected(50)
	if len(rej) == 0 {
		return nil
	}
	insts, _ := a.DB.ListInstances(ctx, 0)
	type owner struct {
		inst *store.Instance
		node string
	}
	byKey := map[string]owner{}
	for _, i := range insts {
		for _, n := range a.CachedNodes(i.ID) {
			byKey[n.NodeKey] = owner{i, n.DisplayName()}
		}
	}
	deny := map[string]bool{}
	if keys, err := a.DB.ListDERPKeys(ctx); err == nil {
		for _, k := range keys {
			if k.Mode == "deny" {
				deny[k.NodeKey] = true
			}
		}
	}
	out := make([]DERPRejectedInfo, 0, len(rej))
	for _, r := range rej {
		info := DERPRejectedInfo{Rejected: r}
		o, known := byKey[r.Key]
		switch {
		case deny[r.Key]:
			info.Reason = "auf der Denylist"
		case known && !o.inst.Enabled:
			info.Reason = "Instanz ist deaktiviert"
		case known && !o.inst.UseCentralDERP:
			info.Reason = "Instanz nutzt den zentralen DERP nicht"
		case known:
			info.Reason = "inzwischen bekannt (wird beim nächsten Versuch zugelassen)"
		default:
			info.Reason = "unbekannter Schlüssel – gelöschtes oder neu angemeldetes Gerät mit altem Schlüssel oder fremder Client"
		}
		if known {
			info.Instance, info.Node = o.inst.Name, o.node
		}
		out = append(out, info)
	}
	return out
}
