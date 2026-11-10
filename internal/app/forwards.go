package app

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/testbild-media/openHeadscaleGUI/internal/config"
	"github.com/testbild-media/openHeadscaleGUI/internal/edge"
	"github.com/testbild-media/openHeadscaleGUI/internal/forward"
	"github.com/testbild-media/openHeadscaleGUI/internal/secure"
	"github.com/testbild-media/openHeadscaleGUI/internal/store"
)

// ForwardRequest is the editable part of a forward.
type ForwardRequest struct {
	Kind             string
	Domain           string
	PublicPort       int
	NodeID           int64
	TargetHost       string
	TargetPort       int
	UpstreamTLS      bool
	UpstreamInsecure bool
	PreserveHost     bool
	AllowCIDRs       string
	BasicAuthUser    string
	BasicAuthPass    string
	Enabled          bool
	Description      string
}

// reservedPorts can never be used for TCP/UDP forwards.
func (a *App) reservedPorts(ctx context.Context) map[string]bool {
	r := map[string]bool{}
	for _, addr := range []string{a.Cfg.HTTPAddr, a.Cfg.HTTPSAddr} {
		if _, p, err := net.SplitHostPort(addr); err == nil {
			r["tcp/"+p] = true
		}
	}
	ds := a.DERPSettings(ctx)
	if ds.STUNPort > 0 {
		r["udp/"+strconv.Itoa(ds.STUNPort)] = true
	}
	insts, _ := a.DB.ListInstances(ctx, 0)
	for _, i := range insts {
		r["udp/"+strconv.Itoa(i.GatewayPort)] = true
		r["tcp/"+strconv.Itoa(i.InternalPort)] = true
	}
	return r
}

func (a *App) validateForward(ctx context.Context, actor Actor, inst *store.Instance, r *ForwardRequest, existing *store.Forward) error {
	var exceptID int64
	if existing != nil {
		exceptID = existing.ID
	}
	switch r.Kind {
	case store.ForwardHTTP:
		r.Domain = NormalizeDomain(r.Domain)
		if existing == nil || existing.Domain != r.Domain {
			if err := a.checkDomainAllowed(ctx, actor, r.Domain); err != nil {
				return err
			}
		}
		if used := a.domainInUse(ctx, r.Domain, 0, exceptID); used != "" {
			return Errf("Die Domain wird bereits verwendet (%s)", used)
		}
		r.PublicPort = 0
	case store.ForwardTCP, store.ForwardUDP:
		r.Domain = ""
		s := a.Settings(ctx)
		if r.PublicPort < s.PortMin || r.PublicPort > s.PortMax {
			if !actor.User.IsSuperadmin() || ValidPort(r.PublicPort) != nil {
				return Errf("Der öffentliche Port muss zwischen %d und %d liegen", s.PortMin, s.PortMax)
			}
		}
		if a.reservedPorts(ctx)[r.Kind+"/"+strconv.Itoa(r.PublicPort)] {
			return Errf("Port %d ist reserviert", r.PublicPort)
		}
		fwds, _ := a.DB.ListForwards(ctx, 0)
		for _, f := range fwds {
			if f.Kind == r.Kind && f.PublicPort == r.PublicPort && f.ID != exceptID {
				return Errf("Port %s/%d wird bereits verwendet", r.Kind, r.PublicPort)
			}
		}
		r.UpstreamTLS, r.UpstreamInsecure, r.BasicAuthUser, r.BasicAuthPass = false, false, "", ""
	default:
		return Errf("Ungültiger Typ")
	}
	if err := ValidPort(r.TargetPort); err != nil {
		return err
	}
	r.TargetHost = strings.TrimSpace(r.TargetHost)
	if r.NodeID != 0 {
		found := false
		for _, n := range a.CachedNodes(inst.ID) {
			if int64(n.ID) == r.NodeID {
				found = true
			}
		}
		if !found {
			return Errf("Das Ziel-Gerät existiert nicht")
		}
		r.TargetHost = ""
	} else {
		if r.TargetHost == "" {
			return Errf("Bitte ein Ziel-Gerät oder eine Ziel-IP angeben")
		}
		addr, err := netip.ParseAddr(r.TargetHost)
		if err != nil {
			return Errf("Bitte eine IP-Adresse als Ziel angeben (oder ein Gerät auswählen)")
		}
		addr = addr.Unmap()
		if !a.targetAllowed(inst, addr) {
			return Errf("Das Ziel %s liegt weder im Tailnet (%s) noch in einem freigegebenen Subnetz dieser Instanz", addr, inst.PrefixV4)
		}
		r.TargetHost = addr.String()
	}
	var err error
	if r.AllowCIDRs, err = ParseCIDRs(r.AllowCIDRs); err != nil {
		return err
	}
	r.Description = strings.TrimSpace(r.Description)
	if len(r.Description) > 200 {
		r.Description = r.Description[:200]
	}
	r.BasicAuthUser = strings.TrimSpace(r.BasicAuthUser)
	if r.BasicAuthUser != "" && strings.ContainsAny(r.BasicAuthUser, ":\r\n") {
		return Errf("Ungültiger Basic-Auth-Benutzer")
	}
	return nil
}

// CreateForward adds a forward.
func (a *App) CreateForward(ctx context.Context, actor Actor, inst *store.Instance, r ForwardRequest) (*store.Forward, error) {
	if !CanManage(actor.User, inst) {
		return nil, ErrForbidden
	}
	if err := a.validateForward(ctx, actor, inst, &r, nil); err != nil {
		return nil, err
	}
	f := &store.Forward{InstanceID: inst.ID}
	if err := a.fillForward(ctx, f, r); err != nil {
		return nil, err
	}
	if err := a.DB.CreateForward(ctx, f); err != nil {
		return nil, err
	}
	a.afterForwardChange(ctx)
	a.Audit(ctx, actor, inst.ID, "forward.create", describeForward(f))
	return f, nil
}

// UpdateForward changes a forward.
func (a *App) UpdateForward(ctx context.Context, actor Actor, inst *store.Instance, f *store.Forward, r ForwardRequest) error {
	if !CanManage(actor.User, inst) || f.InstanceID != inst.ID {
		return ErrForbidden
	}
	if err := a.validateForward(ctx, actor, inst, &r, f); err != nil {
		return err
	}
	if err := a.fillForward(ctx, f, r); err != nil {
		return err
	}
	if err := a.DB.UpdateForward(ctx, f); err != nil {
		return err
	}
	a.afterForwardChange(ctx)
	a.Audit(ctx, actor, inst.ID, "forward.update", describeForward(f))
	return nil
}

// SetForwardEnabled toggles a forward.
func (a *App) SetForwardEnabled(ctx context.Context, actor Actor, inst *store.Instance, f *store.Forward, enabled bool) error {
	if !CanManage(actor.User, inst) || f.InstanceID != inst.ID {
		return ErrForbidden
	}
	f.Enabled = enabled
	if err := a.DB.UpdateForward(ctx, f); err != nil {
		return err
	}
	a.afterForwardChange(ctx)
	a.Audit(ctx, actor, inst.ID, map[bool]string{true: "forward.enable", false: "forward.disable"}[enabled], describeForward(f))
	return nil
}

// DeleteForward removes a forward.
func (a *App) DeleteForward(ctx context.Context, actor Actor, inst *store.Instance, f *store.Forward) error {
	if !CanManage(actor.User, inst) || f.InstanceID != inst.ID {
		return ErrForbidden
	}
	if err := a.DB.DeleteForward(ctx, f.ID); err != nil {
		return err
	}
	a.afterForwardChange(ctx)
	a.Audit(ctx, actor, inst.ID, "forward.delete", describeForward(f))
	return nil
}

func (a *App) fillForward(ctx context.Context, f *store.Forward, r ForwardRequest) error {
	f.Kind, f.Domain, f.PublicPort, f.NodeID, f.TargetHost, f.TargetPort = r.Kind, r.Domain, r.PublicPort, r.NodeID, r.TargetHost, r.TargetPort
	f.UpstreamTLS, f.UpstreamInsecure, f.PreserveHost = r.UpstreamTLS, r.UpstreamInsecure, r.PreserveHost
	f.AllowCIDRs, f.Enabled, f.Description = r.AllowCIDRs, r.Enabled, r.Description
	if r.BasicAuthUser == "" {
		f.BasicAuthUser, f.BasicAuthHash = "", ""
	} else {
		f.BasicAuthUser = r.BasicAuthUser
		if r.BasicAuthPass != "" {
			if err := secure.CheckPasswordPolicy(r.BasicAuthPass, r.BasicAuthUser); err != nil {
				return &UserError{Msg: "Basic-Auth: " + err.Error()}
			}
			h, err := secure.HashPassword(ctx, r.BasicAuthPass)
			if err != nil {
				return err
			}
			f.BasicAuthHash = h
		} else if f.BasicAuthHash == "" {
			return Errf("Bitte ein Basic-Auth-Passwort setzen")
		}
	}
	return nil
}

func describeForward(f *store.Forward) string {
	target := f.TargetHost
	if f.NodeID != 0 {
		target = fmt.Sprintf("node#%d", f.NodeID)
	}
	if f.Kind == store.ForwardHTTP {
		return fmt.Sprintf("https://%s → %s:%d", f.Domain, target, f.TargetPort)
	}
	return fmt.Sprintf("%s/%d → %s:%d", f.Kind, f.PublicPort, target, f.TargetPort)
}

func (a *App) afterForwardChange(ctx context.Context) {
	_ = a.RebuildRoutes(ctx)
	a.SyncForwards(ctx)
}

// targetAllowed reports whether a forward may connect to addr: it must be
// inside the tailnet prefixes of the instance or inside a subnet route that
// is approved for a node of this instance (exit routes do not count).
// Anything else would let the embedded node dial the server's own network
// (tsnet falls back to the system dialer for non-tailnet addresses).
func (a *App) targetAllowed(inst *store.Instance, addr netip.Addr) bool {
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsLoopback() || addr.IsMulticast() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
		return false
	}
	for _, s := range []string{inst.PrefixV4, inst.PrefixV6} {
		if p, err := netip.ParsePrefix(s); err == nil && p.Contains(addr) {
			return true
		}
	}
	for _, n := range a.CachedNodes(inst.ID) {
		for _, r := range n.ApprovedRoutes {
			if isExitRoute(r) {
				continue
			}
			if p, err := netip.ParsePrefix(r); err == nil && p.Bits() > 0 && p.Contains(addr) {
				return true
			}
		}
	}
	return false
}

// ForwardTarget resolves the current tailnet address of a forward.
func (a *App) ForwardTarget(f *store.Forward) (string, error) {
	port := strconv.Itoa(f.TargetPort)
	if f.NodeID == 0 {
		addr, err := netip.ParseAddr(f.TargetHost)
		if err != nil {
			return "", fmt.Errorf("invalid target %q", f.TargetHost)
		}
		inst, err := a.DB.GetInstance(context.Background(), f.InstanceID)
		if err != nil {
			return "", err
		}
		if !a.targetAllowed(inst, addr.Unmap()) {
			return "", fmt.Errorf("target %s is not inside the tailnet or an approved subnet", addr)
		}
		return net.JoinHostPort(addr.Unmap().String(), port), nil
	}
	for _, n := range a.CachedNodes(f.InstanceID) {
		if int64(n.ID) == f.NodeID {
			if ip := n.IPv4(); ip != "" {
				return net.JoinHostPort(ip, port), nil
			}
			if ip := n.IPv6(); ip != "" {
				return net.JoinHostPort(ip, port), nil
			}
		}
	}
	return "", fmt.Errorf("target node %d not found", f.NodeID)
}

func parseAllow(s string) []netip.Prefix {
	p, _ := config.ParsePrefixes(s)
	return p
}

func (a *App) buildHTTPForward(f *store.Forward) http.Handler {
	fc := *f
	ft := edge.ForwardTarget{
		ID: fc.ID, Domain: fc.Domain, UpstreamTLS: fc.UpstreamTLS, Insecure: fc.UpstreamInsecure,
		PreserveHost: fc.PreserveHost, Allow: parseAllow(fc.AllowCIDRs), BasicUser: fc.BasicAuthUser,
		Target: func() (string, error) { return a.ForwardTarget(&fc) },
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return a.GW.Dial(ctx, fc.InstanceID, network, addr)
		},
		C: a.FwdReg.Get(fc.ID),
	}
	if fc.BasicAuthUser != "" && fc.BasicAuthHash != "" {
		ft.CheckBasic = func(user, pass string) bool { return a.checkBasic(&fc, user, pass) }
	}
	return edge.ForwardProxy(ft, a.Log)
}

// checkBasic validates basic-auth credentials with a short-lived cache so
// that Argon2 does not run for every request.
func (a *App) checkBasic(f *store.Forward, user, pass string) bool {
	if !secure.ConstantTimeEqual(user, f.BasicAuthUser) {
		return false
	}
	mac := a.Sealer.MAC(fmt.Sprintf("%d|%d|%s|%s", f.ID, f.UpdatedAt, user, pass))
	if exp, ok := a.basicOK.Load(mac); ok && exp.(int64) > time.Now().Unix() {
		return true
	}
	key := fmt.Sprintf("basic|%d|%s", f.ID, user)
	if a.basicBad.Blocked(key) {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ok, err := secure.VerifyPassword(ctx, f.BasicAuthHash, pass)
	if err != nil || !ok {
		a.basicBad.Fail(key)
		return false
	}
	a.basicOK.Store(mac, time.Now().Add(10*time.Minute).Unix())
	return true
}

// SyncForwards makes the TCP/UDP listeners match the database.
func (a *App) SyncForwards(ctx context.Context) {
	fwds, err := a.DB.ListForwards(ctx, 0)
	if err != nil {
		return
	}
	insts, _ := a.DB.ListInstances(ctx, 0)
	enabled := map[int64]bool{}
	for _, i := range insts {
		enabled[i.ID] = i.Enabled
	}
	var rules []forward.Rule
	for _, f := range fwds {
		if f.Kind == store.ForwardHTTP || !f.Enabled || !enabled[f.InstanceID] {
			continue
		}
		fc := *f
		rules = append(rules, forward.Rule{
			ID: fc.ID, InstanceID: fc.InstanceID, Proto: fc.Kind, Port: fc.PublicPort,
			Allow:   parseAllow(fc.AllowCIDRs),
			Target:  func() (string, error) { return a.ForwardTarget(&fc) },
			Version: fc.UpdatedAt,
		})
	}
	a.Fwd.Sync(rules)
}
