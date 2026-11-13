// Package gateway runs one embedded tailscale node (tsnet, userspace
// networking) per instance. The node makes the server itself a member of
// every tailnet: it is the target for port forwarding, it can be used as an
// exit node and it is used to probe the reachability of clients.
package gateway

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
)

// Hostname is the hostname the gateway registers with.
const Hostname = "ohg-gateway"

// SystemUser is the headscale user owning the gateway nodes.
const SystemUser = "ohg-system"

// Gateway states.
const (
	StateStopped  = "stopped"
	StateStarting = "starting"
	StateRunning  = "running"
	StateError    = "error"
)

// ExitRoutes are advertised by the gateway so it can act as exit node.
var ExitRoutes = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}

// Spec configures a gateway.
type Spec struct {
	ID         int64
	Slug       string
	Dir        string
	ControlURL string
	Port       uint16
	// AuthKey returns a fresh single-use pre-auth key; only called when the
	// node has no state yet (or must re-register).
	AuthKey func(ctx context.Context) (string, error)
	// ExitNode is the initial state of exit-node forwarding (see
	// Manager.SetExitNode).
	ExitNode bool
}

// Status of a gateway.
type Status struct {
	State   string
	Error   string
	IPv4    string
	IPv6    string
	NodeKey string
	Since   time.Time
}

type gw struct {
	spec   Spec
	cancel context.CancelFunc
	done   chan struct{}
	exit   atomic.Bool // forward traffic of exit-node clients

	mu     sync.Mutex
	srv    *tsnet.Server
	status Status
}

func (g *gw) set(state, errMsg string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.status.State != state {
		g.status.Since = time.Now()
	}
	g.status.State = state
	g.status.Error = errMsg
}

// Manager manages the gateways of all instances.
type Manager struct {
	log   *slog.Logger
	debug bool

	mu  sync.Mutex
	gws map[int64]*gw
}

// NewManager creates a gateway manager.
func NewManager(log *slog.Logger, debug bool) *Manager {
	return &Manager{log: log, debug: debug, gws: map[int64]*gw{}}
}

// Start (re)starts the gateway of an instance asynchronously.
func (m *Manager) Start(spec Spec) {
	m.Stop(spec.ID)
	ctx, cancel := context.WithCancel(context.Background())
	g := &gw{spec: spec, cancel: cancel, done: make(chan struct{})}
	g.exit.Store(spec.ExitNode)
	g.status = Status{State: StateStarting, Since: time.Now()}
	m.mu.Lock()
	m.gws[spec.ID] = g
	m.mu.Unlock()
	go m.run(ctx, g)
}

// SetExitNode switches forwarding of exit-node traffic on or off. It mirrors
// the exit route approval in headscale and is a second line of defence for
// peers that send traffic to the gateway without the routes being approved.
func (m *Manager) SetExitNode(id int64, on bool) {
	m.mu.Lock()
	g := m.gws[id]
	m.mu.Unlock()
	if g != nil {
		g.exit.Store(on)
	}
}

// Stop shuts down the gateway of an instance.
func (m *Manager) Stop(id int64) {
	m.mu.Lock()
	g := m.gws[id]
	delete(m.gws, id)
	m.mu.Unlock()
	if g == nil {
		return
	}
	g.cancel()
	<-g.done
}

// StopAll shuts down all gateways.
func (m *Manager) StopAll() {
	m.mu.Lock()
	ids := make([]int64, 0, len(m.gws))
	for id := range m.gws {
		ids = append(ids, id)
	}
	m.mu.Unlock()
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(id int64) { defer wg.Done(); m.Stop(id) }(id)
	}
	wg.Wait()
}

// Reset removes the gateway state so it registers again on next start.
func Reset(dir string) error { return os.RemoveAll(dir) }

func stateFile(dir string) string { return filepath.Join(dir, "tailscaled.state") }

func (m *Manager) run(ctx context.Context, g *gw) {
	defer close(g.done)
	log := m.log.With("instance", g.spec.Slug, "component", "gateway")
	backoff := 2 * time.Second
	for ctx.Err() == nil {
		err := m.runOnce(ctx, g, log)
		if ctx.Err() != nil {
			break
		}
		if err != nil {
			log.Warn("gateway error", "err", err)
			g.set(StateError, err.Error())
		}
		select {
		case <-ctx.Done():
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, time.Minute)
	}
	g.set(StateStopped, "")
}

func (m *Manager) runOnce(ctx context.Context, g *gw, log *slog.Logger) error {
	if err := os.MkdirAll(g.spec.Dir, 0o700); err != nil {
		return err
	}
	g.set(StateStarting, "")
	var authKey string
	if _, err := os.Stat(stateFile(g.spec.Dir)); errors.Is(err, os.ErrNotExist) {
		kctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		k, err := g.spec.AuthKey(kctx)
		cancel()
		if err != nil {
			return fmt.Errorf("creating gateway auth key: %w", err)
		}
		authKey = k
	}
	srv := &tsnet.Server{
		Dir:        g.spec.Dir,
		Hostname:   Hostname,
		ControlURL: g.spec.ControlURL,
		AuthKey:    authKey,
		Port:       g.spec.Port,
		UserLogf: func(format string, args ...any) {
			log.Debug(fmt.Sprintf(format, args...))
		},
	}
	if m.debug {
		srv.Logf = func(format string, args ...any) { log.Debug(fmt.Sprintf(format, args...)) }
	}
	defer srv.Close()
	if err := srv.Start(); err != nil {
		return fmt.Errorf("starting gateway: %w", err)
	}
	if err := installExitForwarding(srv, g.exit.Load); err != nil {
		log.Warn("exit node forwarding unavailable", "err", err)
	}

	upCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	st, err := srv.Up(upCtx)
	cancel()
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		// If control does not know the node anymore (deleted in
		// headscale) the backend waits for an interactive login. Wipe the
		// state so the next attempt registers with a new key.
		if lc, lerr := srv.LocalClient(); lerr == nil {
			sctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
			s, serr := lc.StatusWithoutPeers(sctx)
			scancel()
			if serr == nil && s.BackendState == ipn.NeedsLogin.String() {
				log.Warn("gateway needs login, resetting state")
				srv.Close()
				_ = os.RemoveAll(g.spec.Dir)
				return errors.New("gateway was not registered anymore, registering again")
			}
		}
		return fmt.Errorf("gateway did not come up: %w", err)
	}
	lc, err := srv.LocalClient()
	if err != nil {
		return err
	}
	// Always offer the server as exit node; approval is controlled per
	// instance in headscale.
	pctx, pcancel := context.WithTimeout(ctx, 10*time.Second)
	_, err = lc.EditPrefs(pctx, &ipn.MaskedPrefs{
		Prefs:              ipn.Prefs{AdvertiseRoutes: ExitRoutes},
		AdvertiseRoutesSet: true,
	})
	pcancel()
	if err != nil {
		log.Warn("advertising exit routes failed", "err", err)
	}

	g.mu.Lock()
	g.srv = srv
	g.status.State = StateRunning
	g.status.Error = ""
	g.status.Since = time.Now()
	g.status.IPv4, g.status.IPv6 = "", ""
	if st.Self != nil {
		g.status.NodeKey = st.Self.PublicKey.String()
	}
	for _, ip := range st.TailscaleIPs {
		if ip.Is4() {
			g.status.IPv4 = ip.String()
		} else {
			g.status.IPv6 = ip.String()
		}
	}
	g.mu.Unlock()
	log.Info("gateway running", "ipv4", g.status.IPv4)

	// Watch the backend state; return when it is no longer usable.
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	defer func() {
		g.mu.Lock()
		g.srv = nil
		g.mu.Unlock()
	}()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		sctx, scancel := context.WithTimeout(ctx, 5*time.Second)
		s, err := lc.StatusWithoutPeers(sctx)
		scancel()
		if err != nil {
			continue
		}
		g.mu.Lock()
		for _, ip := range s.TailscaleIPs {
			if ip.Is4() {
				g.status.IPv4 = ip.String()
			} else {
				g.status.IPv6 = ip.String()
			}
		}
		if s.Self != nil {
			g.status.NodeKey = s.Self.PublicKey.String()
		}
		g.mu.Unlock()
		if s.BackendState == ipn.NeedsLogin.String() {
			log.Warn("gateway lost its registration, resetting state")
			srv.Close()
			_ = os.RemoveAll(g.spec.Dir)
			return errors.New("gateway registration lost")
		}
	}
}

func (m *Manager) server(id int64) (*tsnet.Server, error) {
	m.mu.Lock()
	g := m.gws[id]
	m.mu.Unlock()
	if g == nil {
		return nil, errors.New("gateway not started")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.srv == nil {
		return nil, errors.New("gateway not connected")
	}
	return g.srv, nil
}

// Status returns the state of a gateway.
func (m *Manager) Status(id int64) Status {
	m.mu.Lock()
	g := m.gws[id]
	m.mu.Unlock()
	if g == nil {
		return Status{State: StateStopped}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.status
}

// Dial connects to addr inside the tailnet of an instance.
func (m *Manager) Dial(ctx context.Context, id int64, network, addr string) (net.Conn, error) {
	srv, err := m.server(id)
	if err != nil {
		return nil, err
	}
	return srv.Dial(ctx, network, addr)
}

// LocalClient returns the LocalAPI client of a running gateway.
func (m *Manager) LocalClient(id int64) (*local.Client, error) {
	srv, err := m.server(id)
	if err != nil {
		return nil, err
	}
	return srv.LocalClient()
}

// PeerStatus returns the gateway's view of the tailnet.
func (m *Manager) PeerStatus(ctx context.Context, id int64) (*ipnstate.Status, error) {
	lc, err := m.LocalClient(id)
	if err != nil {
		return nil, err
	}
	return lc.Status(ctx)
}

// Ping sends a disco ping to ip from the gateway and returns the result.
func (m *Manager) Ping(ctx context.Context, id int64, ip netip.Addr) (*ipnstate.PingResult, error) {
	lc, err := m.LocalClient(id)
	if err != nil {
		return nil, err
	}
	return lc.Ping(ctx, ip, tailcfg.PingDisco)
}
