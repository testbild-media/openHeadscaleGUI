package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/testbild-media/openHeadscaleGUI/internal/gateway"
	"github.com/testbild-media/openHeadscaleGUI/internal/headscale"
	"github.com/testbild-media/openHeadscaleGUI/internal/store"
)

// DefaultHSUser is the tailnet user created with every instance.
const DefaultHSUser = "default"

// InstanceParams are the user editable instance fields.
type InstanceParams struct {
	Name             string
	Slug             string
	Domain           string
	PrefixV4         string
	PrefixV6         string
	IPAllocation     string
	MagicDNS         bool
	BaseDomain       string
	Nameservers      string
	OverrideLocalDNS bool
	UseCentralDERP   bool
	UsePublicDERP    bool
	GatewayExitNode  bool
	NodeExpiry       string
	EphemeralTimeout string
	OwnerID          int64
}

// DefaultInstanceParams returns sensible defaults for a new instance.
func DefaultInstanceParams() InstanceParams {
	return InstanceParams{
		PrefixV4:         "100.64.0.0/10",
		PrefixV6:         "fd7a:115c:a1e0::/48",
		IPAllocation:     "sequential",
		MagicDNS:         true,
		Nameservers:      "1.1.1.1, 9.9.9.9",
		UseCentralDERP:   true,
		UsePublicDERP:    false,
		GatewayExitNode:  true,
		NodeExpiry:       "0",
		EphemeralTimeout: "30m",
	}
}

// ParamsFromInstance converts an instance to editable params.
func ParamsFromInstance(i *store.Instance) InstanceParams {
	return InstanceParams{
		Name: i.Name, Slug: i.Slug, Domain: i.Domain, PrefixV4: i.PrefixV4, PrefixV6: i.PrefixV6,
		IPAllocation: i.IPAllocation, MagicDNS: i.MagicDNS, BaseDomain: i.BaseDomain, Nameservers: i.Nameservers,
		OverrideLocalDNS: i.OverrideLocalDNS, UseCentralDERP: i.UseCentralDERP, UsePublicDERP: i.UsePublicDERP,
		GatewayExitNode: i.GatewayExitNode, NodeExpiry: i.NodeExpiry, EphemeralTimeout: i.EphemeralTimeout, OwnerID: i.OwnerID,
	}
}

// domainInUse checks all places that claim a domain. exceptInstance and
// exceptForward allow the owner of the domain to keep it.
func (a *App) domainInUse(ctx context.Context, domain string, exceptInstance, exceptForward int64) string {
	if domain == a.Cfg.AdminDomain {
		return "Admin-Oberfläche"
	}
	if ds := a.DERPSettings(ctx); ds.Domain == domain && ds.Domain != "" {
		return "DERP-Server"
	}
	insts, _ := a.DB.ListInstances(ctx, 0)
	for _, i := range insts {
		if i.Domain == domain && i.ID != exceptInstance {
			return "Instanz " + i.Name
		}
	}
	fwds, _ := a.DB.ListForwards(ctx, 0)
	for _, f := range fwds {
		if f.Domain == domain && f.ID != exceptForward {
			return "Port-Forward"
		}
	}
	return ""
}

// checkDomainAllowed enforces the allowed suffixes for normal users.
func (a *App) checkDomainAllowed(ctx context.Context, actor Actor, domain string) error {
	if err := ValidDomain(domain); err != nil {
		return err
	}
	if actor.User.IsSuperadmin() {
		return nil
	}
	suffixes := a.Settings(ctx).AllowedSuffixes
	if len(suffixes) == 0 {
		return nil
	}
	for _, s := range suffixes {
		s = strings.TrimPrefix(strings.ToLower(s), ".")
		if strings.HasSuffix(domain, "."+s) {
			return nil
		}
	}
	return Errf("Die Domain muss auf eine der erlaubten Endungen enden: %s", strings.Join(suffixes, ", "))
}

func (a *App) validateParams(ctx context.Context, actor Actor, p *InstanceParams, existing *store.Instance) error {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" || len(p.Name) > 64 {
		return Errf("Bitte einen Namen (max. 64 Zeichen) angeben")
	}
	p.Domain = NormalizeDomain(p.Domain)
	if existing == nil || existing.Domain != p.Domain {
		if err := a.checkDomainAllowed(ctx, actor, p.Domain); err != nil {
			return err
		}
	}
	var exceptID int64
	if existing != nil {
		exceptID = existing.ID
	}
	if used := a.domainInUse(ctx, p.Domain, exceptID, 0); used != "" {
		return Errf("Die Domain wird bereits verwendet (%s)", used)
	}
	var err error
	if p.PrefixV4, err = ValidPrefixV4(p.PrefixV4); err != nil {
		return err
	}
	if p.PrefixV6, err = ValidPrefixV6(p.PrefixV6); err != nil {
		return err
	}
	if p.IPAllocation != "sequential" && p.IPAllocation != "random" {
		p.IPAllocation = "sequential"
	}
	p.BaseDomain = NormalizeDomain(p.BaseDomain)
	if p.MagicDNS || p.BaseDomain != "" {
		if p.BaseDomain == "" {
			return Errf("MagicDNS benötigt eine Basis-Domain")
		}
		if err := ValidDomain(p.BaseDomain); err != nil {
			return Errf("Ungültige MagicDNS-Basis-Domain")
		}
		if p.BaseDomain == p.Domain || strings.HasSuffix(p.Domain, "."+p.BaseDomain) {
			return Errf("Die MagicDNS-Basis-Domain darf die Server-Domain nicht enthalten (z. B. %s.internal verwenden)", firstLabel(p.Domain))
		}
	}
	var ns []string
	for _, n := range SplitList(p.Nameservers) {
		if err := ValidNameserver(n); err != nil {
			return err
		}
		ns = append(ns, n)
	}
	if len(ns) > 8 {
		return Errf("Maximal 8 DNS-Server")
	}
	p.Nameservers = strings.Join(ns, ",")
	if !p.UseCentralDERP && !p.UsePublicDERP {
		return Errf("Mindestens ein DERP-Relay (zentral oder öffentlich) muss aktiv sein")
	}
	if err := ValidDuration(p.NodeExpiry, true); err != nil {
		return err
	}
	if p.NodeExpiry == "" {
		p.NodeExpiry = "0"
	}
	if err := ValidDuration(p.EphemeralTimeout, false); err != nil {
		return err
	}
	return nil
}

func firstLabel(d string) string {
	l, _, _ := strings.Cut(d, ".")
	return l
}

func (a *App) allocatePorts(ctx context.Context) (int, int, error) {
	internal, gw, err := a.DB.UsedPorts(ctx)
	if err != nil {
		return 0, 0, err
	}
	ip := a.Cfg.InternalPortBase
	for internal[ip] {
		ip++
	}
	gp := a.Cfg.GatewayPortBase
	for gw[gp] {
		gp++
	}
	if ip > 65535 || gp > 65535 {
		return 0, 0, Errf("Keine freien Ports mehr")
	}
	return ip, gp, nil
}

// CreateInstance creates and starts a new instance.
func (a *App) CreateInstance(ctx context.Context, actor Actor, p InstanceParams) (*store.Instance, error) {
	if actor.User == nil {
		return nil, ErrForbidden
	}
	if !actor.User.IsSuperadmin() {
		if !a.Settings(ctx).AllowUserCreate {
			return nil, Errf("Das Anlegen von Instanzen ist für Benutzer deaktiviert")
		}
		n, err := a.DB.CountInstancesByOwner(ctx, actor.User.ID)
		if err != nil {
			return nil, err
		}
		if n >= actor.User.MaxInstances {
			return nil, Errf("Instanz-Limit erreicht (%d)", actor.User.MaxInstances)
		}
		p.OwnerID = actor.User.ID
	}
	if p.OwnerID == 0 {
		p.OwnerID = actor.User.ID
	}
	p.Slug = strings.ToLower(strings.TrimSpace(p.Slug))
	if err := ValidSlug(p.Slug); err != nil {
		return nil, err
	}
	if _, err := a.DB.GetInstanceBySlug(ctx, p.Slug); err == nil {
		return nil, Errf("Der Kurzname %q ist bereits vergeben", p.Slug)
	}
	if p.BaseDomain == "" && p.MagicDNS {
		p.BaseDomain = p.Slug + ".internal"
	}
	if err := a.validateParams(ctx, actor, &p, nil); err != nil {
		return nil, err
	}
	if _, err := a.DB.GetUser(ctx, p.OwnerID); err != nil {
		return nil, Errf("Unbekannter Besitzer")
	}
	ip, gp, err := a.allocatePorts(ctx)
	if err != nil {
		return nil, err
	}
	inst := &store.Instance{
		Slug: p.Slug, Name: p.Name, OwnerID: p.OwnerID, Domain: p.Domain, Enabled: true,
		InternalPort: ip, GatewayPort: gp, PrefixV4: p.PrefixV4, PrefixV6: p.PrefixV6, IPAllocation: p.IPAllocation,
		MagicDNS: p.MagicDNS, BaseDomain: p.BaseDomain, Nameservers: p.Nameservers, OverrideLocalDNS: p.OverrideLocalDNS,
		UseCentralDERP: p.UseCentralDERP, UsePublicDERP: p.UsePublicDERP, GatewayExitNode: p.GatewayExitNode,
		NodeExpiry: p.NodeExpiry, EphemeralTimeout: p.EphemeralTimeout,
	}
	dir := a.InstanceDir(inst.Slug)
	if _, err := os.Stat(dir); err == nil {
		return nil, Errf("Das Datenverzeichnis %s existiert bereits", dir)
	}
	if err := a.DB.CreateInstance(ctx, inst); err != nil {
		return nil, err
	}
	if err := a.startInstance(inst); err != nil {
		a.Log.Error("starting new instance failed", "instance", inst.Slug, "err", err)
	}
	if err := a.RebuildRoutes(ctx); err != nil {
		return nil, err
	}
	a.Audit(ctx, actor, inst.ID, "instance.create", fmt.Sprintf("%s (%s)", inst.Name, inst.Domain))
	return inst, nil
}

// UpdateInstance applies changed settings and restarts the instance if
// needed.
func (a *App) UpdateInstance(ctx context.Context, actor Actor, inst *store.Instance, p InstanceParams) error {
	if !CanManage(actor.User, inst) {
		return ErrForbidden
	}
	if err := a.validateParams(ctx, actor, &p, inst); err != nil {
		return err
	}
	if p.PrefixV4 != inst.PrefixV4 || p.PrefixV6 != inst.PrefixV6 {
		nodes := a.CachedNodes(inst.ID)
		if len(nodes) > 0 {
			return Errf("Die IP-Präfixe können nur geändert werden, solange keine Geräte registriert sind")
		}
	}
	old := *inst
	inst.Name, inst.Domain = p.Name, p.Domain
	inst.PrefixV4, inst.PrefixV6, inst.IPAllocation = p.PrefixV4, p.PrefixV6, p.IPAllocation
	inst.MagicDNS, inst.BaseDomain, inst.Nameservers, inst.OverrideLocalDNS = p.MagicDNS, p.BaseDomain, p.Nameservers, p.OverrideLocalDNS
	inst.UseCentralDERP, inst.UsePublicDERP, inst.GatewayExitNode = p.UseCentralDERP, p.UsePublicDERP, p.GatewayExitNode
	inst.NodeExpiry, inst.EphemeralTimeout = p.NodeExpiry, p.EphemeralTimeout
	if actor.User.IsSuperadmin() && p.OwnerID != 0 && p.OwnerID != inst.OwnerID {
		if _, err := a.DB.GetUser(ctx, p.OwnerID); err != nil {
			return Errf("Unbekannter Besitzer")
		}
		inst.OwnerID = p.OwnerID
	}
	if err := a.DB.UpdateInstance(ctx, inst); err != nil {
		return err
	}
	newCfg, _ := a.renderConfig(inst)
	oldCfg, _ := a.renderConfig(&old)
	if inst.Enabled && !bytes.Equal(newCfg, oldCfg) {
		if err := a.startInstance(inst); err != nil {
			return err
		}
	}
	if err := a.RebuildRoutes(ctx); err != nil {
		return err
	}
	a.Trigger(inst.ID)
	a.Audit(ctx, actor, inst.ID, "instance.update", inst.Name)
	return nil
}

// SetInstanceEnabled starts or stops an instance.
func (a *App) SetInstanceEnabled(ctx context.Context, actor Actor, inst *store.Instance, enabled bool) error {
	if !CanManage(actor.User, inst) {
		return ErrForbidden
	}
	inst.Enabled = enabled
	if err := a.DB.UpdateInstance(ctx, inst); err != nil {
		return err
	}
	if enabled {
		if err := a.startInstance(inst); err != nil {
			return err
		}
	} else {
		a.stopInstance(inst.ID)
	}
	_ = a.RebuildRoutes(ctx)
	a.SyncForwards(ctx)
	action := "instance.disable"
	if enabled {
		action = "instance.enable"
	}
	a.Audit(ctx, actor, inst.ID, action, inst.Name)
	return nil
}

// RestartInstance restarts headscale and the gateway.
func (a *App) RestartInstance(ctx context.Context, actor Actor, inst *store.Instance) error {
	if !CanManage(actor.User, inst) {
		return ErrForbidden
	}
	if !inst.Enabled {
		return Errf("Die Instanz ist deaktiviert")
	}
	a.GW.Stop(inst.ID)
	if err := a.startInstance(inst); err != nil {
		return err
	}
	a.Audit(ctx, actor, inst.ID, "instance.restart", inst.Name)
	return nil
}

// DeleteInstance stops an instance, moves its data to the trash folder and
// removes it from the database.
func (a *App) DeleteInstance(ctx context.Context, actor Actor, inst *store.Instance) error {
	if !CanManage(actor.User, inst) {
		return ErrForbidden
	}
	l := a.opLock(inst.ID)
	l.Lock()
	defer l.Unlock()
	a.stopInstance(inst.ID)
	a.HS.Forget(inst.ID)
	dir := a.InstanceDir(inst.Slug)
	trash := filepath.Join(a.Cfg.DataDir, "trash", fmt.Sprintf("%s-%s", inst.Slug, time.Now().Format("20060102-150405")))
	if _, err := os.Stat(dir); err == nil {
		if err := os.Rename(dir, trash); err != nil {
			return fmt.Errorf("moving instance data to trash: %w", err)
		}
	}
	if err := a.DB.DeleteInstance(ctx, inst.ID); err != nil {
		return err
	}
	a.hsProxy.Delete(inst.ID)
	a.clients.Delete(inst.ID)
	a.nodeMu.Lock()
	delete(a.nodes, inst.ID)
	delete(a.nodesAt, inst.ID)
	delete(a.gwNodeIDs, inst.ID)
	a.nodeMu.Unlock()
	_ = a.RebuildRoutes(ctx)
	a.SyncForwards(ctx)
	a.rebuildDERPIndex()
	a.Audit(ctx, actor, inst.ID, "instance.delete", fmt.Sprintf("%s (%s), Daten in %s", inst.Name, inst.Domain, trash))
	return nil
}

func (a *App) renderConfig(inst *store.Instance) ([]byte, error) {
	return headscale.RenderConfig(headscale.ConfigParams{
		Dir:              a.InstanceDir(inst.Slug),
		ServerURL:        a.Cfg.PublicURL(inst.Domain),
		Port:             inst.InternalPort,
		PrefixV4:         inst.PrefixV4,
		PrefixV6:         inst.PrefixV6,
		Allocation:       inst.IPAllocation,
		MagicDNS:         inst.MagicDNS,
		BaseDomain:       inst.BaseDomain,
		Nameservers:      inst.NameserverList(),
		OverrideLocalDNS: inst.OverrideLocalDNS,
		UseCentralDERP:   inst.UseCentralDERP && a.DERPSettings(context.Background()).Enabled,
		UsePublicDERP:    inst.UsePublicDERP || !a.DERPSettings(context.Background()).Enabled,
		NodeExpiry:       inst.NodeExpiry,
		EphemeralTimeout: inst.EphemeralTimeout,
		LogLevel:         map[bool]string{true: "debug", false: "info"}[a.Cfg.LogLevel == "debug"],
	})
}

func (a *App) derpMapFor(inst *store.Instance) []byte {
	ds := a.DERPSettings(context.Background())
	if !ds.Enabled || !inst.UseCentralDERP || ds.Domain == "" {
		return nil
	}
	stun := ds.STUNPort
	if stun == 0 {
		stun = -1
	}
	b, err := headscale.RenderDERPMap(headscale.DERPNode{
		RegionID: ds.RegionID, RegionCode: ds.RegionCode, RegionName: ds.RegionName,
		Hostname: ds.Domain, IPv4: ds.IPv4, IPv6: ds.IPv6, STUNPort: stun, DERPPort: a.Cfg.HTTPSPort(),
	})
	if err != nil {
		a.Log.Error("rendering DERP map failed", "err", err)
		return nil
	}
	return b
}

// startInstance (re)starts the headscale process of an instance. The
// gateway is started once headscale is ready (onInstanceReady).
func (a *App) startInstance(inst *store.Instance) error {
	cfg, err := a.renderConfig(inst)
	if err != nil {
		return err
	}
	return a.HS.Start(headscale.Spec{
		ID: inst.ID, Slug: inst.Slug, Dir: a.InstanceDir(inst.Slug), Port: inst.InternalPort,
		Config: cfg, DERPMap: a.derpMapFor(inst),
	})
}

func (a *App) stopInstance(id int64) {
	a.GW.Stop(id)
	a.HS.Stop(id)
}

// onInstanceReady runs after every headscale (re)start.
func (a *App) onInstanceReady(id int64) {
	ctx, cancel := context.WithTimeout(a.ctx, 2*time.Minute)
	defer cancel()
	inst, err := a.DB.GetInstance(ctx, id)
	if err != nil {
		return
	}
	c, err := a.Client(ctx, inst)
	if err != nil {
		a.Log.Error("instance API not usable", "instance", inst.Slug, "err", err)
		return
	}
	for _, u := range []string{gateway.SystemUser, DefaultHSUser} {
		if _, err := a.ensureHSUser(ctx, c, u); err != nil {
			a.Log.Error("ensuring tailnet user failed", "instance", inst.Slug, "user", u, "err", err)
		}
	}
	if a.GW.Status(id).State == gateway.StateStopped {
		a.startGateway(inst)
	}
	a.Trigger(id)
}

func (a *App) startGateway(inst *store.Instance) {
	id := inst.ID
	a.GW.Start(gateway.Spec{
		ID:         id,
		Slug:       inst.Slug,
		Dir:        headscale.GatewayDir(a.InstanceDir(inst.Slug)),
		ControlURL: "http://127.0.0.1:" + strconv.Itoa(inst.InternalPort),
		Port:       uint16(inst.GatewayPort),
		AuthKey: func(ctx context.Context) (string, error) {
			cur, err := a.DB.GetInstance(ctx, id)
			if err != nil {
				return "", err
			}
			c, err := a.Client(ctx, cur)
			if err != nil {
				return "", err
			}
			u, err := a.ensureHSUser(ctx, c, gateway.SystemUser)
			if err != nil {
				return "", err
			}
			k, err := c.CreatePreAuthKey(ctx, headscale.CreatePreAuthKeyRequest{
				UserID: uint64(u.ID), Expiration: time.Now().Add(gatewayKeyExpiration),
			})
			if err != nil {
				return "", err
			}
			return k.Key, nil
		},
	})
}

// ResetGateway forces the gateway to register again.
func (a *App) ResetGateway(ctx context.Context, actor Actor, inst *store.Instance) error {
	if !CanManage(actor.User, inst) {
		return ErrForbidden
	}
	a.GW.Stop(inst.ID)
	if gid := a.GatewayNodeID(inst.ID); gid != 0 {
		if c, err := a.Client(ctx, inst); err == nil {
			_ = c.DeleteNode(ctx, gid)
		}
	}
	if err := gateway.Reset(headscale.GatewayDir(a.InstanceDir(inst.Slug))); err != nil {
		return err
	}
	a.startGateway(inst)
	a.Audit(ctx, actor, inst.ID, "gateway.reset", inst.Name)
	return nil
}

func (a *App) ensureHSUser(ctx context.Context, c *headscale.Client, name string) (*headscale.User, error) {
	users, err := c.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		if u.Name == name {
			u := u
			return &u, nil
		}
	}
	return c.CreateUser(ctx, name, "")
}

// Client returns an authenticated API client for a running instance. The
// API key is created on first use via the headscale CLI.
func (a *App) Client(ctx context.Context, inst *store.Instance) (*headscale.Client, error) {
	if a.HS.Status(inst.ID).State != headscale.StateRunning {
		return nil, ErrNotRunning
	}
	if v, ok := a.clients.Load(inst.ID); ok {
		return v.(*headscale.Client), nil
	}
	l := a.opLock(-inst.ID) // separate lock for key bootstrap
	l.Lock()
	defer l.Unlock()
	if v, ok := a.clients.Load(inst.ID); ok {
		return v.(*headscale.Client), nil
	}
	base := "http://127.0.0.1:" + strconv.Itoa(inst.InternalPort)
	cur, err := a.DB.GetInstance(ctx, inst.ID)
	if err != nil {
		return nil, err
	}
	if key, err := a.Sealer.OpenString(cur.APIKeyEnc); err == nil && key != "" {
		c := headscale.NewClient(base, key)
		if err := c.Health(ctx); err == nil {
			a.clients.Store(inst.ID, c)
			return c, nil
		} else if !headscale.IsUnauthorized(err) {
			return nil, err
		}
	}
	out, err := a.HS.RunCLI(ctx, a.InstanceDir(inst.Slug), "apikeys", "create", "--expiration", "3650d", "-o", "json")
	if err != nil {
		return nil, err
	}
	var key string
	if err := json.Unmarshal(bytes.TrimSpace(out), &key); err != nil || key == "" {
		key = strings.Trim(strings.TrimSpace(string(out)), `"`)
	}
	if key == "" {
		return nil, fmt.Errorf("headscale returned no API key")
	}
	if err := a.DB.SetInstanceAPIKey(ctx, inst.ID, a.Sealer.SealString(key)); err != nil {
		return nil, err
	}
	c := headscale.NewClient(base, key)
	a.clients.Store(inst.ID, c)
	a.Log.Info("created headscale API key", "instance", inst.Slug)
	return c, nil
}

// InvalidateClient drops a cached client (e.g. after 401).
func (a *App) InvalidateClient(id int64) { a.clients.Delete(id) }

// ---- node cache ----

// CachedNodes returns the last known node list of an instance.
func (a *App) CachedNodes(id int64) []headscale.Node {
	a.nodeMu.RLock()
	defer a.nodeMu.RUnlock()
	return a.nodes[id]
}

// GatewayNodeID returns the headscale node ID of the gateway (0 = unknown).
func (a *App) GatewayNodeID(id int64) uint64 {
	a.nodeMu.RLock()
	defer a.nodeMu.RUnlock()
	return a.gwNodeIDs[id]
}

// Nodes returns the node list, refreshing it if older than maxAge.
func (a *App) Nodes(ctx context.Context, inst *store.Instance, maxAge time.Duration) ([]headscale.Node, error) {
	a.nodeMu.RLock()
	at, ok := a.nodesAt[inst.ID]
	nodes := a.nodes[inst.ID]
	a.nodeMu.RUnlock()
	if ok && time.Since(at) < maxAge {
		return nodes, nil
	}
	return a.refreshNodes(ctx, inst)
}

func (a *App) refreshNodes(ctx context.Context, inst *store.Instance) ([]headscale.Node, error) {
	c, err := a.Client(ctx, inst)
	if err != nil {
		return nil, err
	}
	nodes, err := c.ListNodes(ctx)
	if headscale.IsUnauthorized(err) {
		a.InvalidateClient(inst.ID)
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	gwKey := a.GW.Status(inst.ID).NodeKey
	var gwID uint64
	for _, n := range nodes {
		if gwKey != "" && n.NodeKey == gwKey {
			gwID = uint64(n.ID)
		}
	}
	a.nodeMu.Lock()
	a.nodes[inst.ID] = nodes
	a.nodesAt[inst.ID] = time.Now()
	if gwID != 0 || gwKey == "" {
		a.gwNodeIDs[inst.ID] = gwID
	}
	a.nodeMu.Unlock()
	return nodes, nil
}

// FindNode returns a node by ID from a fresh list.
func (a *App) FindNode(ctx context.Context, inst *store.Instance, id uint64) (*headscale.Node, error) {
	nodes, err := a.Nodes(ctx, inst, 2*time.Second)
	if err != nil {
		return nil, err
	}
	for i := range nodes {
		if uint64(nodes[i].ID) == id {
			return &nodes[i], nil
		}
	}
	return nil, Errf("Gerät nicht gefunden")
}

// ReservedIPv4 returns the gateway address of an instance (network+1).
func ReservedIPv4(inst *store.Instance) netip.Addr {
	a, _ := headscale.FirstHost(inst.PrefixV4)
	return a
}

// ReservedIPv6 returns the gateway IPv6 address of an instance.
func ReservedIPv6(inst *store.Instance) netip.Addr {
	a, _ := headscale.FirstHost(inst.PrefixV6)
	return a
}

// InstanceSummary is shown on the dashboard.
type InstanceSummary struct {
	Inst        *store.Instance
	Owner       string
	State       headscale.State
	StateError  string
	Gateway     string
	GatewayIP   string
	NodesTotal  int
	NodesOnline int
	Pending     int
	URL         string
	RxRate      float64
	TxRate      float64
	AvgPingMs   float64
	Reachable   int
	Probed      int
}

// Summaries lists the instances visible to the user.
func (a *App) Summaries(ctx context.Context, u *store.User) ([]InstanceSummary, error) {
	var owner int64
	if !u.IsSuperadmin() {
		owner = u.ID
	}
	insts, err := a.DB.ListInstances(ctx, owner)
	if err != nil {
		return nil, err
	}
	users, _ := a.DB.ListUsers(ctx)
	names := map[int64]string{}
	for _, x := range users {
		names[x.ID] = x.Username
	}
	pending, _ := a.DB.CountOpenPending(ctx)
	var out []InstanceSummary
	for _, inst := range insts {
		st := a.HS.Status(inst.ID)
		gs := a.GW.Status(inst.ID)
		s := InstanceSummary{
			Inst: inst, Owner: names[inst.OwnerID], State: st.State, StateError: st.LastError,
			Gateway: gs.State, GatewayIP: gs.IPv4, Pending: pending[inst.ID], URL: a.Cfg.PublicURL(inst.Domain),
		}
		if !inst.Enabled {
			s.State = "disabled"
		}
		gw := a.GatewayNodeID(inst.ID)
		for _, n := range a.CachedNodes(inst.ID) {
			if uint64(n.ID) == gw || n.UserName() == gateway.SystemUser {
				continue
			}
			s.NodesTotal++
			if n.Online {
				s.NodesOnline++
			}
		}
		mv := a.Mon.Instance(inst.ID)
		s.RxRate, s.TxRate, s.AvgPingMs, s.Reachable, s.Probed = mv.RxRate, mv.TxRate, mv.AvgPingMs, mv.Reachable, mv.Probed
		out = append(out, s)
	}
	return out, nil
}
