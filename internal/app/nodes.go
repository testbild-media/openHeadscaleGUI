package app

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/testbild-media/openHeadscaleGUI/internal/edge"
	"github.com/testbild-media/openHeadscaleGUI/internal/gateway"
	"github.com/testbild-media/openHeadscaleGUI/internal/headscale"
	"github.com/testbild-media/openHeadscaleGUI/internal/store"
)

func (a *App) mustClient(ctx context.Context, actor Actor, inst *store.Instance) (*headscale.Client, error) {
	if !CanManage(actor.User, inst) {
		return nil, ErrForbidden
	}
	return a.Client(ctx, inst)
}

func (a *App) isGateway(inst *store.Instance, nodeID uint64) bool {
	return nodeID != 0 && a.GatewayNodeID(inst.ID) == nodeID
}

func hsErr(err error) error {
	if err == nil {
		return nil
	}
	if IsUserError(err) {
		return err
	}
	return Errf("%s", strings.TrimPrefix(err.Error(), "headscale: "))
}

// RenameNode sets the MagicDNS name of a node.
func (a *App) RenameNode(ctx context.Context, actor Actor, inst *store.Instance, nodeID uint64, name string) error {
	c, err := a.mustClient(ctx, actor, inst)
	if err != nil {
		return err
	}
	if a.isGateway(inst, nodeID) {
		return Errf("Der Server-Node kann nicht umbenannt werden")
	}
	n, err := NodeName(name)
	if err != nil {
		return err
	}
	if err := c.RenameNode(ctx, nodeID, n); err != nil {
		return hsErr(err)
	}
	a.Audit(ctx, actor, inst.ID, "node.rename", fmt.Sprintf("#%d → %s", nodeID, n))
	a.Trigger(inst.ID)
	return nil
}

// DeleteNode removes a node from the tailnet.
func (a *App) DeleteNode(ctx context.Context, actor Actor, inst *store.Instance, nodeID uint64) error {
	c, err := a.mustClient(ctx, actor, inst)
	if err != nil {
		return err
	}
	if a.isGateway(inst, nodeID) {
		return Errf("Der Server-Node kann nicht gelöscht werden (stattdessen „Gateway neu registrieren“ verwenden)")
	}
	n, _ := a.FindNode(ctx, inst, nodeID)
	if err := c.DeleteNode(ctx, nodeID); err != nil {
		return hsErr(err)
	}
	name := fmt.Sprintf("#%d", nodeID)
	if n != nil {
		name = n.DisplayName()
	}
	a.Audit(ctx, actor, inst.ID, "node.delete", name)
	_, _ = a.refreshNodes(ctx, inst)
	return nil
}

// ExpireNode forces a node to re-authenticate.
func (a *App) ExpireNode(ctx context.Context, actor Actor, inst *store.Instance, nodeID uint64) error {
	c, err := a.mustClient(ctx, actor, inst)
	if err != nil {
		return err
	}
	if a.isGateway(inst, nodeID) {
		return Errf("Der Server-Node kann nicht abgemeldet werden")
	}
	if err := c.ExpireNode(ctx, nodeID); err != nil {
		return hsErr(err)
	}
	a.Audit(ctx, actor, inst.ID, "node.expire", fmt.Sprintf("#%d", nodeID))
	return nil
}

// SetNodeKeyExpiry disables or sets the key expiry of a node.
func (a *App) SetNodeKeyExpiry(ctx context.Context, actor Actor, inst *store.Instance, nodeID uint64, never bool, days int) error {
	c, err := a.mustClient(ctx, actor, inst)
	if err != nil {
		return err
	}
	if never {
		err = c.DisableNodeExpiry(ctx, nodeID)
	} else {
		if days < 1 || days > 3650 {
			return Errf("Ablauf: 1–3650 Tage")
		}
		err = c.SetNodeExpiry(ctx, nodeID, time.Now().Add(time.Duration(days)*24*time.Hour))
	}
	if err != nil {
		return hsErr(err)
	}
	a.Audit(ctx, actor, inst.ID, "node.expiry", fmt.Sprintf("#%d never=%v days=%d", nodeID, never, days))
	return nil
}

// SetNodeTags replaces the ACL tags of a node.
func (a *App) SetNodeTags(ctx context.Context, actor Actor, inst *store.Instance, nodeID uint64, tags string) error {
	c, err := a.mustClient(ctx, actor, inst)
	if err != nil {
		return err
	}
	list := SplitList(tags)
	for _, t := range list {
		if err := ValidTag(t); err != nil {
			return err
		}
	}
	if err := c.SetTags(ctx, nodeID, list); err != nil {
		return hsErr(err)
	}
	a.Audit(ctx, actor, inst.ID, "node.tags", fmt.Sprintf("#%d %s", nodeID, strings.Join(list, ",")))
	return nil
}

// SetRouteApproval approves or revokes one advertised route. route
// "exit" toggles both exit routes.
func (a *App) SetRouteApproval(ctx context.Context, actor Actor, inst *store.Instance, nodeID uint64, route string, approve bool) error {
	c, err := a.mustClient(ctx, actor, inst)
	if err != nil {
		return err
	}
	n, err := a.FindNode(ctx, inst, nodeID)
	if err != nil {
		return err
	}
	var targets []string
	if route == "exit" {
		targets = exitRoutes
	} else {
		p, err := netip.ParsePrefix(route)
		if err != nil {
			return Errf("Ungültige Route")
		}
		targets = []string{p.Masked().String()}
	}
	desired := []string{}
	for _, r := range n.ApprovedRoutes {
		if !slices.Contains(targets, r) {
			desired = append(desired, r)
		}
	}
	if approve {
		for _, t := range targets {
			if !slices.Contains(n.AvailableRoutes, t) && route != "exit" {
				return Errf("Das Gerät bewirbt die Route %s nicht", t)
			}
			if slices.Contains(n.AvailableRoutes, t) {
				desired = append(desired, t)
			}
		}
	}
	if a.isGateway(inst, nodeID) && route == "exit" {
		inst.GatewayExitNode = approve
		if err := a.DB.UpdateInstance(ctx, inst); err != nil {
			return err
		}
	}
	if err := c.SetApprovedRoutes(ctx, nodeID, desired); err != nil {
		return hsErr(err)
	}
	verb := "revoke"
	if approve {
		verb = "approve"
	}
	a.Audit(ctx, actor, inst.ID, "route."+verb, fmt.Sprintf("%s: %s", n.DisplayName(), route))
	_, _ = a.refreshNodes(ctx, inst)
	return nil
}

// ApproveAllRoutes approves every advertised route of a node.
func (a *App) ApproveAllRoutes(ctx context.Context, actor Actor, inst *store.Instance, nodeID uint64) error {
	c, err := a.mustClient(ctx, actor, inst)
	if err != nil {
		return err
	}
	n, err := a.FindNode(ctx, inst, nodeID)
	if err != nil {
		return err
	}
	if err := c.SetApprovedRoutes(ctx, nodeID, n.AvailableRoutes); err != nil {
		return hsErr(err)
	}
	a.Audit(ctx, actor, inst.ID, "route.approve_all", n.DisplayName())
	_, _ = a.refreshNodes(ctx, inst)
	return nil
}

// ValidateNodeIP checks whether ip can be assigned to nodeID.
func (a *App) ValidateNodeIP(ctx context.Context, inst *store.Instance, nodeID uint64, ip string) (string, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil || !addr.Is4() {
		return "", Errf("Bitte eine gültige IPv4-Adresse angeben")
	}
	p, _ := netip.ParsePrefix(inst.PrefixV4)
	if !p.Contains(addr) || addr == p.Masked().Addr() {
		return "", Errf("Die IP muss im Netz %s liegen", inst.PrefixV4)
	}
	if addr == quad100 || chromeOSRange.Contains(addr) {
		return "", Errf("Diese IP ist von Tailscale reserviert")
	}
	if addr == ReservedIPv4(inst) && !a.isGateway(inst, nodeID) {
		return "", Errf("%s ist für den Server reserviert", addr)
	}
	if last := lastAddr(p); addr == last {
		return "", Errf("Die Broadcast-Adresse kann nicht vergeben werden")
	}
	nodes, err := a.Nodes(ctx, inst, 2*time.Second)
	if err == nil {
		for _, n := range nodes {
			if n.IPv4() == addr.String() && uint64(n.ID) != nodeID {
				return "", Errf("%s wird bereits von %s verwendet", addr, n.DisplayName())
			}
		}
	}
	return addr.String(), nil
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	host := 32 - p.Bits()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	v |= (1 << host) - 1
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// SetNodeIP assigns a fixed IPv4 to a node (restarts the instance briefly).
func (a *App) SetNodeIP(ctx context.Context, actor Actor, inst *store.Instance, nodeID uint64, ip string) error {
	if !CanManage(actor.User, inst) {
		return ErrForbidden
	}
	if a.isGateway(inst, nodeID) {
		return Errf("Die Server-IP ist fest auf %s reserviert", ReservedIPv4(inst))
	}
	addr, err := a.ValidateNodeIP(ctx, inst, nodeID, ip)
	if err != nil {
		return err
	}
	n, err := a.FindNode(ctx, inst, nodeID)
	if err != nil {
		return err
	}
	if n.IPv4() == addr {
		return nil
	}
	l := a.opLock(inst.ID)
	l.Lock()
	defer l.Unlock()
	if err := a.applyIPChangesLocked(ctx, inst, []headscale.IPChange{{NodeID: nodeID, IPv4: addr}}); err != nil {
		return hsErr(err)
	}
	// keep a matching client profile in sync
	if profiles, err := a.DB.ListProfiles(ctx, inst.ID); err == nil {
		for _, p := range profiles {
			if p.NodeID == int64(nodeID) && p.DesiredIPv4 != "" && p.DesiredIPv4 != addr {
				p.DesiredIPv4 = addr
				_ = a.DB.UpdateProfile(ctx, p)
			}
		}
	}
	a.Audit(ctx, actor, inst.ID, "node.ip", fmt.Sprintf("%s: %s → %s", n.DisplayName(), n.IPv4(), addr))
	return nil
}

// ---- tailnet users ----

// HSUsers lists the tailnet users of an instance.
func (a *App) HSUsers(ctx context.Context, actor Actor, inst *store.Instance) ([]headscale.User, error) {
	c, err := a.mustClient(ctx, actor, inst)
	if err != nil {
		return nil, err
	}
	users, err := c.ListUsers(ctx)
	if err != nil {
		return nil, hsErr(err)
	}
	slices.SortFunc(users, func(x, y headscale.User) int { return strings.Compare(x.Name, y.Name) })
	return users, nil
}

// CreateHSUser creates a tailnet user.
func (a *App) CreateHSUser(ctx context.Context, actor Actor, inst *store.Instance, name, display string) error {
	c, err := a.mustClient(ctx, actor, inst)
	if err != nil {
		return err
	}
	name = strings.ToLower(strings.TrimSpace(name))
	if err := ValidHSUser(name); err != nil {
		return err
	}
	if name == gateway.SystemUser {
		return Errf("Dieser Name ist reserviert")
	}
	if _, err := c.CreateUser(ctx, name, strings.TrimSpace(display)); err != nil {
		return hsErr(err)
	}
	a.Audit(ctx, actor, inst.ID, "hsuser.create", name)
	return nil
}

// RenameHSUser renames a tailnet user.
func (a *App) RenameHSUser(ctx context.Context, actor Actor, inst *store.Instance, id uint64, newName string) error {
	c, err := a.mustClient(ctx, actor, inst)
	if err != nil {
		return err
	}
	newName = strings.ToLower(strings.TrimSpace(newName))
	if err := ValidHSUser(newName); err != nil {
		return err
	}
	users, err := c.ListUsers(ctx)
	if err != nil {
		return hsErr(err)
	}
	for _, u := range users {
		if uint64(u.ID) == id && u.Name == gateway.SystemUser {
			return Errf("Der System-Benutzer kann nicht umbenannt werden")
		}
	}
	if newName == gateway.SystemUser {
		return Errf("Dieser Name ist reserviert")
	}
	if err := c.RenameUser(ctx, id, newName); err != nil {
		return hsErr(err)
	}
	a.Audit(ctx, actor, inst.ID, "hsuser.rename", fmt.Sprintf("#%d → %s", id, newName))
	return nil
}

// DeleteHSUser deletes a tailnet user (must not own nodes).
func (a *App) DeleteHSUser(ctx context.Context, actor Actor, inst *store.Instance, id uint64) error {
	c, err := a.mustClient(ctx, actor, inst)
	if err != nil {
		return err
	}
	users, err := c.ListUsers(ctx)
	if err != nil {
		return hsErr(err)
	}
	var name string
	for _, u := range users {
		if uint64(u.ID) == id {
			name = u.Name
		}
	}
	if name == gateway.SystemUser {
		return Errf("Der System-Benutzer kann nicht gelöscht werden")
	}
	for _, n := range a.CachedNodes(inst.ID) {
		if n.User != nil && uint64(n.User.ID) == id {
			return Errf("Der Benutzer besitzt noch Geräte")
		}
	}
	if err := c.DeleteUser(ctx, id); err != nil {
		return hsErr(err)
	}
	a.Audit(ctx, actor, inst.ID, "hsuser.delete", name)
	return nil
}

func (a *App) hsUserID(ctx context.Context, c *headscale.Client, name string) (uint64, error) {
	users, err := c.ListUsers(ctx)
	if err != nil {
		return 0, hsErr(err)
	}
	for _, u := range users {
		if u.Name == name {
			return uint64(u.ID), nil
		}
	}
	return 0, Errf("Unbekannter Tailnet-Benutzer %q", name)
}

// ---- pre-auth keys ----

// KeyRequest describes a new pre-auth key.
type KeyRequest struct {
	HSUser    string
	Reusable  bool
	Ephemeral bool
	Hours     int
	Tags      string
}

// PreAuthKeys lists the pre-auth keys of an instance (without system keys).
func (a *App) PreAuthKeys(ctx context.Context, actor Actor, inst *store.Instance) ([]headscale.PreAuthKey, error) {
	c, err := a.mustClient(ctx, actor, inst)
	if err != nil {
		return nil, err
	}
	keys, err := c.ListPreAuthKeys(ctx)
	if err != nil {
		return nil, hsErr(err)
	}
	out := keys[:0]
	listed := map[int64]bool{} // key ID -> usable
	now := time.Now()
	for _, k := range keys {
		if k.User != nil && k.User.Name == gateway.SystemUser {
			continue
		}
		listed[int64(k.ID)] = KeyUsable(k, now)
		out = append(out, k)
	}
	// Drop stored copies of keys that can no longer be used. A key missing
	// from the list may have been created concurrently, so it is only
	// dropped after a grace period.
	if stored, err := a.DB.AuthKeyIDs(ctx, inst.ID); err == nil {
		for id, created := range stored {
			usable, ok := listed[id]
			if (ok && !usable) || (!ok && created < now.Add(-time.Minute).Unix()) {
				_ = a.DB.DeleteAuthKey(ctx, inst.ID, id)
			}
		}
	}
	slices.SortFunc(out, func(x, y headscale.PreAuthKey) int { return int(y.ID) - int(x.ID) })
	return out, nil
}

// KeyUsable reports whether a device can still register with k.
func KeyUsable(k headscale.PreAuthKey, now time.Time) bool {
	return !k.Expired(now) && (k.Reusable || !k.Used)
}

// CreatePreAuthKey creates a key and returns it. An encrypted copy is kept
// so that the connect command can be shown again while the key is usable.
func (a *App) CreatePreAuthKey(ctx context.Context, actor Actor, inst *store.Instance, r KeyRequest) (*headscale.PreAuthKey, error) {
	c, err := a.mustClient(ctx, actor, inst)
	if err != nil {
		return nil, err
	}
	if r.HSUser == gateway.SystemUser {
		return nil, Errf("Dieser Benutzer ist reserviert")
	}
	uid, err := a.hsUserID(ctx, c, r.HSUser)
	if err != nil {
		return nil, err
	}
	if r.Hours < 1 || r.Hours > 24*365 {
		return nil, Errf("Gültigkeit: 1 Stunde bis 365 Tage")
	}
	tags := SplitList(r.Tags)
	for _, t := range tags {
		if err := ValidTag(t); err != nil {
			return nil, err
		}
	}
	k, err := c.CreatePreAuthKey(ctx, headscale.CreatePreAuthKeyRequest{
		UserID: uid, Reusable: r.Reusable, Ephemeral: r.Ephemeral,
		Expiration: time.Now().Add(time.Duration(r.Hours) * time.Hour), Tags: tags,
	})
	if err != nil {
		return nil, hsErr(err)
	}
	exp := time.Now().Add(time.Duration(r.Hours) * time.Hour)
	if k.Expiration != nil && !k.Expiration.IsZero() {
		exp = *k.Expiration
	}
	if err := a.DB.SaveAuthKey(ctx, inst.ID, int64(k.ID), a.Sealer.SealString(k.Key), exp.Unix()); err != nil {
		a.Log.Warn("storing pre-auth key failed", "instance", inst.Slug, "key", k.ID, "err", err)
	}
	a.Audit(ctx, actor, inst.ID, "key.create", fmt.Sprintf("#%d user=%s reusable=%v ephemeral=%v hours=%d", k.ID, r.HSUser, r.Reusable, r.Ephemeral, r.Hours))
	return k, nil
}

// RevealPreAuthKey returns a stored, still usable key including its secret.
func (a *App) RevealPreAuthKey(ctx context.Context, actor Actor, inst *store.Instance, id uint64) (*headscale.PreAuthKey, error) {
	keys, err := a.PreAuthKeys(ctx, actor, inst)
	if err != nil {
		return nil, err
	}
	idx := slices.IndexFunc(keys, func(k headscale.PreAuthKey) bool { return uint64(k.ID) == id })
	if id == 0 || idx < 0 {
		return nil, Errf("Schlüssel #%d existiert nicht (mehr)", id)
	}
	k := keys[idx]
	if !KeyUsable(k, time.Now()) {
		return nil, Errf("Schlüssel #%d ist abgelaufen oder bereits verwendet – bitte einen neuen erstellen", id)
	}
	enc, err := a.DB.GetAuthKey(ctx, inst.ID, int64(id))
	if errors.Is(err, store.ErrNotFound) {
		return nil, Errf("Schlüssel #%d wurde nicht gespeichert (vor dem Update erstellt) – bitte einen neuen erstellen", id)
	} else if err != nil {
		return nil, err
	}
	secret, err := a.Sealer.OpenString(enc)
	if err != nil || secret == "" {
		return nil, fmt.Errorf("decrypt pre-auth key %d: %w", id, err)
	}
	k.Key = secret
	a.Audit(ctx, actor, inst.ID, "key.show", fmt.Sprintf("#%d", id))
	return &k, nil
}

// ExpirePreAuthKey expires a key.
func (a *App) ExpirePreAuthKey(ctx context.Context, actor Actor, inst *store.Instance, id uint64) error {
	c, err := a.mustClient(ctx, actor, inst)
	if err != nil {
		return err
	}
	if err := c.ExpirePreAuthKey(ctx, id); err != nil {
		return hsErr(err)
	}
	_ = a.DB.DeleteAuthKey(ctx, inst.ID, int64(id))
	a.Audit(ctx, actor, inst.ID, "key.expire", fmt.Sprintf("#%d", id))
	return nil
}

// DeletePreAuthKey deletes a key.
func (a *App) DeletePreAuthKey(ctx context.Context, actor Actor, inst *store.Instance, id uint64) error {
	c, err := a.mustClient(ctx, actor, inst)
	if err != nil {
		return err
	}
	if err := c.DeletePreAuthKey(ctx, id); err != nil {
		return hsErr(err)
	}
	_ = a.DB.DeleteAuthKey(ctx, inst.ID, int64(id))
	a.Audit(ctx, actor, inst.ID, "key.delete", fmt.Sprintf("#%d", id))
	return nil
}

// ---- client profiles ----

// ProfileRequest describes a planned client.
type ProfileRequest struct {
	Name       string
	HSUser     string
	IPv4       string
	AutoExit   bool
	AutoRoutes string
	Reusable   bool
	Hours      int
	Tags       string
}

// CreateProfile creates a client profile with a single-use key.
func (a *App) CreateProfile(ctx context.Context, actor Actor, inst *store.Instance, r ProfileRequest) (*store.ClientProfile, *headscale.PreAuthKey, error) {
	if !CanManage(actor.User, inst) {
		return nil, nil, ErrForbidden
	}
	name, err := NodeName(r.Name)
	if err != nil {
		return nil, nil, err
	}
	routes, err := ParseRoutes(r.AutoRoutes)
	if err != nil {
		return nil, nil, err
	}
	ip := ""
	if strings.TrimSpace(r.IPv4) != "" {
		if ip, err = a.ValidateNodeIP(ctx, inst, 0, r.IPv4); err != nil {
			return nil, nil, err
		}
		profiles, _ := a.DB.ListProfiles(ctx, inst.ID)
		for _, p := range profiles {
			if p.DesiredIPv4 == ip {
				return nil, nil, Errf("Die IP %s ist bereits für das Profil %s reserviert", ip, p.Name)
			}
		}
	}
	if r.Hours == 0 {
		r.Hours = 24 * 7
	}
	key, err := a.CreatePreAuthKey(ctx, actor, inst, KeyRequest{HSUser: r.HSUser, Reusable: false, Hours: r.Hours, Tags: r.Tags})
	if err != nil {
		return nil, nil, err
	}
	p := &store.ClientProfile{
		InstanceID: inst.ID, Name: name, HSUser: r.HSUser, DesiredIPv4: ip, PreAuthKeyID: int64(key.ID),
		AutoExit: r.AutoExit, AutoRoutes: strings.Join(routes, ","), Status: store.ProfileWaiting,
	}
	if err := a.DB.CreateProfile(ctx, p); err != nil {
		return nil, nil, err
	}
	a.Audit(ctx, actor, inst.ID, "profile.create", fmt.Sprintf("%s ip=%s", name, ip))
	return p, key, nil
}

// UpdateProfile changes the desired settings of a profile.
func (a *App) UpdateProfile(ctx context.Context, actor Actor, inst *store.Instance, p *store.ClientProfile, r ProfileRequest) error {
	if !CanManage(actor.User, inst) || p.InstanceID != inst.ID {
		return ErrForbidden
	}
	name, err := NodeName(r.Name)
	if err != nil {
		return err
	}
	routes, err := ParseRoutes(r.AutoRoutes)
	if err != nil {
		return err
	}
	ip := ""
	if strings.TrimSpace(r.IPv4) != "" {
		if ip, err = a.ValidateNodeIP(ctx, inst, uint64(p.NodeID), r.IPv4); err != nil {
			return err
		}
	}
	p.Name, p.DesiredIPv4, p.AutoExit, p.AutoRoutes = name, ip, r.AutoExit, strings.Join(routes, ",")
	if err := a.DB.UpdateProfile(ctx, p); err != nil {
		return err
	}
	a.Audit(ctx, actor, inst.ID, "profile.update", name)
	a.Trigger(inst.ID)
	return nil
}

// DeleteProfile removes a profile (the node, if any, stays).
func (a *App) DeleteProfile(ctx context.Context, actor Actor, inst *store.Instance, p *store.ClientProfile) error {
	if !CanManage(actor.User, inst) || p.InstanceID != inst.ID {
		return ErrForbidden
	}
	if p.NodeID == 0 && p.PreAuthKeyID != 0 {
		if c, err := a.Client(ctx, inst); err == nil {
			_ = c.ExpirePreAuthKey(ctx, uint64(p.PreAuthKeyID))
		}
	}
	if p.PreAuthKeyID != 0 {
		_ = a.DB.DeleteAuthKey(ctx, inst.ID, p.PreAuthKeyID)
	}
	if err := a.DB.DeleteProfile(ctx, p.ID); err != nil {
		return err
	}
	a.Audit(ctx, actor, inst.ID, "profile.delete", p.Name)
	return nil
}

// RenewProfileKey replaces the key of a profile with a new single-use key,
// e.g. to re-register a device after it was removed or switched to another
// tailnet. An unused old key is revoked.
func (a *App) RenewProfileKey(ctx context.Context, actor Actor, inst *store.Instance, p *store.ClientProfile, hours int) (*headscale.PreAuthKey, error) {
	if !CanManage(actor.User, inst) || p.InstanceID != inst.ID {
		return nil, ErrForbidden
	}
	c, err := a.mustClient(ctx, actor, inst)
	if err != nil {
		return nil, err
	}
	if hours == 0 {
		hours = 24 * 7
	}
	old := p.PreAuthKeyID
	var oldKey *headscale.PreAuthKey
	if old != 0 {
		if keys, err := c.ListPreAuthKeys(ctx); err == nil {
			for i := range keys {
				if int64(keys[i].ID) == old {
					oldKey = &keys[i]
				}
			}
		}
	}
	tags := ""
	if oldKey != nil {
		tags = strings.Join(oldKey.ACLTags, ",")
	}
	key, err := a.CreatePreAuthKey(ctx, actor, inst, KeyRequest{HSUser: p.HSUser, Hours: hours, Tags: tags})
	if err != nil {
		return nil, err
	}
	if oldKey != nil && !oldKey.Used && !oldKey.Expired(time.Now()) {
		_ = c.ExpirePreAuthKey(ctx, uint64(old))
	}
	if old != 0 {
		_ = a.DB.DeleteAuthKey(ctx, inst.ID, old)
	}
	p.PreAuthKeyID = int64(key.ID)
	if p.NodeID == 0 {
		p.Status, p.LastError = store.ProfileWaiting, ""
	}
	if err := a.DB.UpdateProfile(ctx, p); err != nil {
		return nil, err
	}
	a.Audit(ctx, actor, inst.ID, "profile.newkey", fmt.Sprintf("%s key=#%d", p.Name, key.ID))
	return key, nil
}

// ---- interactive registrations ----

var registerPage = template.Must(template.New("r").Parse(`<!doctype html>
<html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Gerät wartet auf Freigabe</title>
<style>
:root{color-scheme:light dark}
body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;background:#0b1220;color:#e2e8f0;margin:0;min-height:100vh;display:grid;place-items:center}
main{max-width:34rem;margin:1rem;padding:2rem;border-radius:16px;background:#111a2e;border:1px solid #1f2b46}
h1{font-size:1.4rem;margin:0 0 .5rem}p{color:#9fb0cc;line-height:1.5}
code{display:block;background:#0b1220;border:1px solid #1f2b46;border-radius:8px;padding:.6rem .8rem;word-break:break-all;color:#7dd3fc;margin:.5rem 0 1rem}
.dot{display:inline-block;width:.6rem;height:.6rem;border-radius:50%;background:#f59e0b;margin-right:.5rem;animation:p 1.5s infinite}
@keyframes p{50%{opacity:.3}}
small{color:#64748b}
</style></head><body><main>
<h1><span class="dot"></span>Gerät wartet auf Freigabe</h1>
<p>Die Anmeldung an <strong>{{.Name}}</strong> wurde registriert. Ein Administrator muss dieses Gerät jetzt in der Verwaltung freigeben.
Sobald das passiert ist, verbindet sich das Gerät automatisch – dieses Fenster kann geschlossen werden.</p>
<p>Anfrage-ID (zum Abgleich mit dem Administrator):</p>
<code>{{.ID}}</code>
<small>{{.Domain}}</small>
</main></body></html>`))

// handleRegister intercepts the headscale registration page.
func (a *App) handleRegister(w http.ResponseWriter, r *http.Request, instanceID int64, authID string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if !ValidAuthID(authID) {
		http.NotFound(w, r)
		return
	}
	inst, err := a.DB.GetInstance(r.Context(), instanceID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ip := edge.ClientIP(r).String()
	exists := false
	if list, err := a.DB.ListPending(r.Context(), inst.ID, false, 500); err == nil {
		for _, p := range list {
			if p.AuthID == authID {
				exists = true
			}
		}
	}
	if !exists {
		if !a.regLimit.Allow(ip) {
			http.Error(w, "too many registration attempts, try again later", http.StatusTooManyRequests)
			return
		}
		ok, err := a.DB.UpsertPending(r.Context(), &store.PendingRegistration{
			InstanceID: inst.ID, AuthID: authID, SourceIP: ip, UserAgent: r.UserAgent(),
		}, maxPendingPerInst)
		if err != nil || !ok {
			http.Error(w, "too many pending registrations", http.StatusTooManyRequests)
			return
		}
		a.Log.Info("registration request", "instance", inst.Slug, "ip", ip)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	registerPage.Execute(w, map[string]any{"Name": inst.Name, "ID": authID, "Domain": inst.Domain})
}

// ApproveRequest describes an approval decision.
type ApproveRequest struct {
	HSUser string
	Name   string
	IPv4   string
}

// ApprovePending registers a waiting device.
func (a *App) ApprovePending(ctx context.Context, actor Actor, inst *store.Instance, p *store.PendingRegistration, r ApproveRequest) (*headscale.Node, error) {
	c, err := a.mustClient(ctx, actor, inst)
	if err != nil {
		return nil, err
	}
	if p.InstanceID != inst.ID || p.Status != store.PendingOpen && p.Status != store.PendingExpired {
		return nil, Errf("Die Anfrage ist nicht mehr offen")
	}
	if r.HSUser == gateway.SystemUser || r.HSUser == "" {
		return nil, Errf("Bitte einen Tailnet-Benutzer wählen")
	}
	ip := ""
	if strings.TrimSpace(r.IPv4) != "" {
		if ip, err = a.ValidateNodeIP(ctx, inst, 0, r.IPv4); err != nil {
			return nil, err
		}
	}
	name := ""
	if strings.TrimSpace(r.Name) != "" {
		if name, err = NodeName(r.Name); err != nil {
			return nil, err
		}
	}
	n, err := c.AuthRegister(ctx, r.HSUser, p.AuthID)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "not found") || strings.Contains(strings.ToLower(err.Error()), "expired") {
			_ = a.DB.DecidePending(ctx, p.ID, store.PendingExpired, actor.User.ID, 0, err.Error())
			return nil, Errf("Die Anfrage ist abgelaufen – bitte am Gerät erneut „tailscale up“ ausführen")
		}
		return nil, hsErr(err)
	}
	var nodeID uint64
	if n != nil {
		nodeID = uint64(n.ID)
	}
	_ = a.DB.DecidePending(ctx, p.ID, store.PendingApproved, actor.User.ID, int64(nodeID), "")
	a.Audit(ctx, actor, inst.ID, "pending.approve", fmt.Sprintf("%s user=%s", p.AuthID[:22], r.HSUser))
	if nodeID != 0 {
		if name != "" {
			_ = c.RenameNode(ctx, nodeID, name)
		}
		if ip != "" && (n == nil || n.IPv4() != ip) {
			l := a.opLock(inst.ID)
			l.Lock()
			err := a.applyIPChangesLocked(ctx, inst, []headscale.IPChange{{NodeID: nodeID, IPv4: ip}})
			l.Unlock()
			if err != nil {
				return n, Errf("Gerät freigegeben, aber die IP konnte nicht gesetzt werden: %v", err)
			}
		}
	}
	_, _ = a.refreshNodes(ctx, inst)
	a.rebuildDERPIndex()
	return n, nil
}

// RejectPending rejects a waiting device.
func (a *App) RejectPending(ctx context.Context, actor Actor, inst *store.Instance, p *store.PendingRegistration) error {
	c, err := a.mustClient(ctx, actor, inst)
	if err != nil {
		return err
	}
	if p.InstanceID != inst.ID {
		return ErrForbidden
	}
	_ = c.AuthReject(ctx, p.AuthID)
	if err := a.DB.DecidePending(ctx, p.ID, store.PendingRejected, actor.User.ID, 0, ""); err != nil {
		return err
	}
	a.Audit(ctx, actor, inst.ID, "pending.reject", p.AuthID[:22])
	return nil
}

// ManualRegister registers a device from a pasted URL/command/auth ID.
func (a *App) ManualRegister(ctx context.Context, actor Actor, inst *store.Instance, text string, r ApproveRequest) (*headscale.Node, error) {
	if !CanManage(actor.User, inst) {
		return nil, ErrForbidden
	}
	authID, ok := ParseAuthID(text)
	if !ok {
		return nil, Errf("Keine gültige Anfrage-ID gefunden (Format hskey-authreq-…)")
	}
	_, _ = a.DB.UpsertPending(ctx, &store.PendingRegistration{InstanceID: inst.ID, AuthID: authID, SourceIP: "manuell"}, maxPendingPerInst+50)
	list, err := a.DB.ListPending(ctx, inst.ID, false, 500)
	if err != nil {
		return nil, err
	}
	for _, p := range list {
		if p.AuthID == authID {
			if p.Status != store.PendingOpen {
				_ = a.DB.DecidePending(ctx, p.ID, store.PendingOpen, 0, 0, "")
				p.Status = store.PendingOpen
			}
			return a.ApprovePending(ctx, actor, inst, p, r)
		}
	}
	return nil, Errf("Anfrage konnte nicht angelegt werden")
}

// ---- policy ----

// DefaultPolicy is a starting point for the ACL editor.
const DefaultPolicy = `{
  // Gruppen fassen Tailnet-Benutzer zusammen.
  "groups": {
    "group:admins": ["default@"],
  },

  // Tags können Geräten per Pre-Auth-Key oder in der Verwaltung zugewiesen werden.
  "tagOwners": {
    "tag:server": ["group:admins"],
  },

  "acls": [
    // Der ohg-Server (Gateway, 100.64.0.1) muss die Ziele der Port-Forwards erreichen.
    {"action": "accept", "src": ["ohg-system@"], "dst": ["*:*"]},

    // Alle Geräte dürfen sich gegenseitig erreichen.
    {"action": "accept", "src": ["*"], "dst": ["*:*"]},
  ],

  // Exit-Nodes und Subnetze werden in der Verwaltung einzeln freigegeben.
}
`

// GetPolicy returns the stored ACL policy.
func (a *App) GetPolicy(ctx context.Context, actor Actor, inst *store.Instance) (string, error) {
	c, err := a.mustClient(ctx, actor, inst)
	if err != nil {
		return "", err
	}
	p, err := c.GetPolicy(ctx)
	return p, hsErr(err)
}

// CheckPolicy validates a policy.
func (a *App) CheckPolicy(ctx context.Context, actor Actor, inst *store.Instance, policy string) error {
	c, err := a.mustClient(ctx, actor, inst)
	if err != nil {
		return err
	}
	if len(policy) > 512<<10 {
		return Errf("Die Policy ist zu groß")
	}
	return hsErr(c.CheckPolicy(ctx, policy))
}

// SetPolicy stores a policy.
func (a *App) SetPolicy(ctx context.Context, actor Actor, inst *store.Instance, policy string) error {
	c, err := a.mustClient(ctx, actor, inst)
	if err != nil {
		return err
	}
	if len(policy) > 512<<10 {
		return Errf("Die Policy ist zu groß")
	}
	if err := c.SetPolicy(ctx, policy); err != nil {
		return hsErr(err)
	}
	a.Audit(ctx, actor, inst.ID, "policy.set", fmt.Sprintf("%d Bytes", len(policy)))
	return nil
}
