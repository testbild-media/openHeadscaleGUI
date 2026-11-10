// Package app wires all components together and implements the business
// logic used by the web GUI.
package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/ipn/ipnstate"

	"github.com/testbild-media/openHeadscaleGUI/internal/config"
	"github.com/testbild-media/openHeadscaleGUI/internal/derp"
	"github.com/testbild-media/openHeadscaleGUI/internal/edge"
	"github.com/testbild-media/openHeadscaleGUI/internal/forward"
	"github.com/testbild-media/openHeadscaleGUI/internal/gateway"
	"github.com/testbild-media/openHeadscaleGUI/internal/headscale"
	"github.com/testbild-media/openHeadscaleGUI/internal/monitor"
	"github.com/testbild-media/openHeadscaleGUI/internal/ratelimit"
	"github.com/testbild-media/openHeadscaleGUI/internal/secure"
	"github.com/testbild-media/openHeadscaleGUI/internal/store"
)

// Version is set at build time.
var Version = "dev"

// Actor identifies who performs an action (for permissions and audit).
type Actor struct {
	User *store.User
	IP   string
}

// App is the application core.
type App struct {
	Cfg    *config.Config
	DB     *store.Store
	Sealer *secure.Sealer
	Log    *slog.Logger

	HS     *headscale.Manager
	GW     *gateway.Manager
	DERP   *derp.Service
	Fwd    *forward.Manager
	FwdReg *forward.Registry
	Mon    *monitor.Monitor
	Edge   *edge.Server

	// Web is the admin GUI handler (set before Start).
	Web http.Handler

	HeadscaleVersion string

	routes   atomic.Pointer[map[string]http.Handler]
	hsProxy  sync.Map // instanceID -> http.Handler
	opLocks  sync.Map // instanceID -> *sync.Mutex
	clients  sync.Map // instanceID -> *headscale.Client
	reconCh  chan int64
	regLimit *ratelimit.Limiter
	basicOK  sync.Map // mac -> expiry unix
	basicBad *ratelimit.Failures
	// ipFailUntil suppresses automatic IP changes after a failure.
	ipFailUntil sync.Map

	nodeMu    sync.RWMutex
	nodes     map[int64][]headscale.Node
	nodesAt   map[int64]time.Time
	gwNodeIDs map[int64]uint64

	derpIndex    atomic.Pointer[map[string]int64]
	derpRefresh  sync.Mutex
	derpLastFull time.Time

	ctx    context.Context
	cancel context.CancelFunc
}

// New creates the application (opens the database).
func New(cfg *config.Config, log *slog.Logger) (*App, error) {
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return nil, err
	}
	for _, d := range []string{"instances", "trash", "acme", "derp"} {
		if err := os.MkdirAll(filepath.Join(cfg.DataDir, d), 0o750); err != nil {
			return nil, err
		}
	}
	db, err := store.Open(filepath.Join(cfg.DataDir, "ohg.db"))
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}
	key, err := secure.LoadOrCreateMasterKey(filepath.Join(cfg.DataDir, "master.key"))
	if err != nil {
		db.Close()
		return nil, err
	}
	sealer, err := secure.NewSealer(key)
	if err != nil {
		db.Close()
		return nil, err
	}
	a := &App{
		Cfg: cfg, DB: db, Sealer: sealer, Log: log,
		FwdReg:    forward.NewRegistry(),
		reconCh:   make(chan int64, 64),
		regLimit:  ratelimit.New(1.0/30, 10),
		basicBad:  ratelimit.NewFailures(10, 10*time.Minute, 15*time.Minute),
		nodes:     map[int64][]headscale.Node{},
		nodesAt:   map[int64]time.Time{},
		gwNodeIDs: map[int64]uint64{},
	}
	a.ctx, a.cancel = context.WithCancel(context.Background())
	empty := map[string]http.Handler{}
	a.routes.Store(&empty)
	idx := map[string]int64{}
	a.derpIndex.Store(&idx)
	return a, nil
}

// Close releases the database (used by CLI commands).
func (a *App) Close() error { return a.DB.Close() }

// Start launches all services.
func (a *App) Start() error {
	a.HS = headscale.NewManager(a.Cfg.HeadscaleBin, a.Log.With("component", "headscale"))
	a.HS.OnReady = a.onInstanceReady
	if v, err := a.HS.CheckBinary(a.ctx); err != nil {
		a.Log.Error("headscale binary check failed", "err", err)
	} else {
		a.HeadscaleVersion = v
		a.Log.Info("headscale binary", "path", a.Cfg.HeadscaleBin, "version", v)
	}
	a.GW = gateway.NewManager(a.Log.With("component", "gateway"), a.Cfg.LogLevel == "debug")
	var err error
	a.DERP, err = derp.New(a.Cfg.DataDir, a.Log.With("component", "derp"), a.admitDERP)
	if err != nil {
		return err
	}
	if err := a.DERP.Apply(a.DERPSettings(a.ctx)); err != nil {
		a.Log.Error("DERP start failed", "err", err)
	}
	a.Fwd = forward.NewManager(func(ctx context.Context, id int64, network, addr string) (net.Conn, error) {
		return a.GW.Dial(ctx, id, network, addr)
	}, a.FwdReg, a.Log.With("component", "forward"), "")
	a.Mon = monitor.New(monitorSource{a}, a.Log.With("component", "monitor"))

	insts, err := a.DB.ListInstances(a.ctx, 0)
	if err != nil {
		return err
	}
	for _, inst := range insts {
		if !inst.Enabled {
			continue
		}
		if err := a.startInstance(inst); err != nil {
			a.Log.Error("starting instance failed", "instance", inst.Slug, "err", err)
		}
	}
	if err := a.RebuildRoutes(a.ctx); err != nil {
		return err
	}
	a.SyncForwards(a.ctx)

	a.Edge = edge.New(a.Cfg, a.Log.With("component", "edge"), a, a.certHook)
	if err := a.Edge.Start(); err != nil {
		return err
	}
	go a.reconcileLoop()
	go a.housekeeping()
	go a.Mon.Run(a.ctx)
	return nil
}

// Shutdown stops all services.
func (a *App) Shutdown(ctx context.Context) {
	a.cancel()
	if a.Edge != nil {
		a.Edge.Shutdown(ctx)
	}
	if a.Fwd != nil {
		a.Fwd.StopAll()
	}
	if a.GW != nil {
		a.GW.StopAll()
	}
	if a.HS != nil {
		a.HS.StopAll()
	}
	if a.DERP != nil {
		a.DERP.Close()
	}
	a.DB.Close()
}

func (a *App) certHook(host string, cert *tls.Certificate) *tls.Certificate {
	ds := a.DERP.Settings()
	if ds.Enabled && host == ds.Domain {
		return a.DERP.AddMetaCert(cert)
	}
	return cert
}

func (a *App) opLock(id int64) *sync.Mutex {
	v, _ := a.opLocks.LoadOrStore(id, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// InstanceDir returns the data directory of an instance.
func (a *App) InstanceDir(slug string) string {
	return filepath.Join(a.Cfg.DataDir, "instances", slug)
}

// ---- routing ----

// Route implements edge.Router.
func (a *App) Route(host string) http.Handler {
	m := *a.routes.Load()
	return m[host]
}

// RebuildRoutes recomputes the host -> handler table.
func (a *App) RebuildRoutes(ctx context.Context) error {
	m := map[string]http.Handler{}
	if a.Web != nil && a.Cfg.AdminDomain != "" {
		m[a.Cfg.AdminDomain] = a.Web
	}
	ds := a.DERPSettings(ctx)
	if ds.Enabled && ds.Domain != "" {
		m[ds.Domain] = a.DERP
	}
	insts, err := a.DB.ListInstances(ctx, 0)
	if err != nil {
		return err
	}
	enabled := map[int64]bool{}
	for _, inst := range insts {
		if !inst.Enabled {
			m[inst.Domain] = disabledHandler
			continue
		}
		enabled[inst.ID] = true
		h, ok := a.hsProxy.Load(inst.ID)
		if !ok {
			id := inst.ID
			h = edge.HeadscaleProxy(inst.InternalPort, func(w http.ResponseWriter, r *http.Request, authID string) {
				a.handleRegister(w, r, id, authID)
			}, a.Log)
			a.hsProxy.Store(inst.ID, h)
		}
		m[inst.Domain] = h.(http.Handler)
	}
	fwds, err := a.DB.ListForwards(ctx, 0)
	if err != nil {
		return err
	}
	for _, f := range fwds {
		if f.Kind != store.ForwardHTTP || f.Domain == "" {
			continue
		}
		if !f.Enabled || !enabled[f.InstanceID] {
			m[f.Domain] = disabledHandler
			continue
		}
		m[f.Domain] = a.buildHTTPForward(f)
	}
	a.routes.Store(&m)
	return nil
}

var disabledHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, "service disabled", http.StatusServiceUnavailable)
})

// ---- settings ----

// Setting keys.
const (
	SetAllowUserCreate   = "users.allow_create"
	SetDefaultMaxInst    = "users.default_max_instances"
	SetAllowedSuffixes   = "domains.allowed_suffixes"
	SetPortMin           = "forward.port_min"
	SetPortMax           = "forward.port_max"
	SetRequire2FA        = "security.require_2fa"
	SetSetupTokenHash    = "setup.token_hash"
	SetAuditRetention    = "audit.retention_days"
	SetDERPEnabled       = "derp.enabled"
	SetDERPDomain        = "derp.domain"
	SetDERPRegionID      = "derp.region_id"
	SetDERPRegionCode    = "derp.region_code"
	SetDERPRegionName    = "derp.region_name"
	SetDERPSTUNPort      = "derp.stun_port"
	SetDERPVerify        = "derp.verify_clients"
	SetDERPFailOpen      = "derp.fail_open"
	SetDERPIPv4          = "derp.ipv4"
	SetDERPIPv6          = "derp.ipv6"
	defaultPortMin       = 20000
	defaultPortMax       = 20999
	defaultMaxInstances  = 3
	defaultAuditDays     = 365
	pendingExpiry        = time.Hour
	maxPendingPerInst    = 100
	nodeCacheMaxAge      = 20 * time.Second
	gatewayKeyExpiration = time.Hour
)

// GlobalSettings are the superadmin-editable settings.
type GlobalSettings struct {
	AllowUserCreate bool
	DefaultMaxInst  int
	AllowedSuffixes []string
	PortMin         int
	PortMax         int
	Require2FA      bool
	AuditDays       int
}

// Settings returns the global settings.
func (a *App) Settings(ctx context.Context) GlobalSettings {
	return GlobalSettings{
		AllowUserCreate: a.DB.GetSettingBool(ctx, SetAllowUserCreate, true),
		DefaultMaxInst:  a.DB.GetSettingInt(ctx, SetDefaultMaxInst, defaultMaxInstances),
		AllowedSuffixes: SplitList(a.DB.GetSetting(ctx, SetAllowedSuffixes, "")),
		PortMin:         a.DB.GetSettingInt(ctx, SetPortMin, defaultPortMin),
		PortMax:         a.DB.GetSettingInt(ctx, SetPortMax, defaultPortMax),
		Require2FA:      a.Cfg.Require2FA || a.DB.GetSettingBool(ctx, SetRequire2FA, false),
		AuditDays:       a.DB.GetSettingInt(ctx, SetAuditRetention, defaultAuditDays),
	}
}

// SaveSettings stores the global settings.
func (a *App) SaveSettings(ctx context.Context, actor Actor, s GlobalSettings) error {
	if !actor.User.IsSuperadmin() {
		return ErrForbidden
	}
	if s.PortMin < 1024 || s.PortMax > 65535 || s.PortMin > s.PortMax {
		return Errf("Ungültiger Portbereich (1024–65535)")
	}
	if s.DefaultMaxInst < 0 || s.DefaultMaxInst > 1000 {
		return Errf("Ungültige Instanz-Quote")
	}
	if s.AuditDays < 7 || s.AuditDays > 3650 {
		return Errf("Audit-Aufbewahrung: 7–3650 Tage")
	}
	for _, suf := range s.AllowedSuffixes {
		if err := ValidDomain(suf); err != nil {
			return Errf("Ungültiges Domain-Suffix %q", suf)
		}
	}
	b := func(v bool) string {
		if v {
			return "1"
		}
		return "0"
	}
	err := a.DB.SetSettings(ctx, map[string]string{
		SetAllowUserCreate: b(s.AllowUserCreate),
		SetDefaultMaxInst:  strconv.Itoa(s.DefaultMaxInst),
		SetAllowedSuffixes: joinList(s.AllowedSuffixes),
		SetPortMin:         strconv.Itoa(s.PortMin),
		SetPortMax:         strconv.Itoa(s.PortMax),
		SetRequire2FA:      b(s.Require2FA),
		SetAuditRetention:  strconv.Itoa(s.AuditDays),
	})
	if err == nil {
		a.Audit(ctx, actor, 0, "settings.update", "")
	}
	return err
}

func joinList(l []string) string {
	out := ""
	for i, s := range l {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}

// ErrForbidden is returned when the actor lacks permissions.
var ErrForbidden = errors.New("forbidden")

// ErrNotRunning is returned when an instance is not running.
var ErrNotRunning = Errf("Die Instanz läuft nicht")

// Audit writes an audit log entry.
func (a *App) Audit(ctx context.Context, actor Actor, instanceID int64, action, detail string) {
	e := store.AuditEntry{IP: actor.IP, InstanceID: instanceID, Action: action, Detail: detail}
	if actor.User != nil {
		e.UserID, e.Username = actor.User.ID, actor.User.Username
	}
	if err := a.DB.Audit(context.WithoutCancel(ctx), e); err != nil {
		a.Log.Error("audit write failed", "err", err)
	}
	a.Log.Info("audit", "user", e.Username, "ip", e.IP, "instance", instanceID, "action", action, "detail", detail)
}

// CanManage reports whether user may manage inst.
func CanManage(u *store.User, inst *store.Instance) bool {
	if u == nil || inst == nil || u.Disabled {
		return false
	}
	return u.IsSuperadmin() || inst.OwnerID == u.ID
}

// housekeeping runs periodic cleanups.
func (a *App) housekeeping() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		ctx := a.ctx
		_ = a.DB.PurgeSessions(ctx, time.Now().Add(-a.Cfg.SessionIdle).Unix())
		_ = a.DB.ExpirePending(ctx, time.Now().Add(-pendingExpiry).Unix(), time.Now().Add(-30*24*time.Hour).Unix())
		days := a.Settings(ctx).AuditDays
		_ = a.DB.PurgeAudit(ctx, time.Now().Add(-time.Duration(days)*24*time.Hour).Unix())
		now := time.Now().Unix()
		a.basicOK.Range(func(k, v any) bool {
			if v.(int64) < now {
				a.basicOK.Delete(k)
			}
			return true
		})
		select {
		case <-a.ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ---- monitor source ----

type monitorSource struct{ a *App }

func (s monitorSource) RunningInstances() []int64 {
	var out []int64
	insts, err := s.a.DB.ListInstances(s.a.ctx, 0)
	if err != nil {
		return nil
	}
	for _, i := range insts {
		if i.Enabled && s.a.HS.Status(i.ID).State == headscale.StateRunning {
			out = append(out, i.ID)
		}
	}
	return out
}

func (s monitorSource) CachedNodes(id int64) []headscale.Node { return s.a.CachedNodes(id) }
func (s monitorSource) GatewayNodeID(id int64) uint64         { return s.a.GatewayNodeID(id) }
func (s monitorSource) PeerStatus(ctx context.Context, id int64) (*ipnstate.Status, error) {
	return s.a.GW.PeerStatus(ctx, id)
}
func (s monitorSource) Ping(ctx context.Context, id int64, ip netip.Addr) (*ipnstate.PingResult, error) {
	return s.a.GW.Ping(ctx, id, ip)
}
func (s monitorSource) DERPClients() []derp.Client {
	c, _ := s.a.DERP.Clients(5000)
	return c
}
func (s monitorSource) DERPStats() derp.Stats                       { return s.a.DERP.Stats() }
func (s monitorSource) ForwardCounters() map[int64]forward.Snapshot { return s.a.FwdReg.Snapshot() }
