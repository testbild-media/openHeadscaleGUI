// Package derp embeds a DERP relay and a STUN server. Client verification
// is done by an admission callback that knows the node keys of all
// instances.
package derp

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/derp/derpserver"
	"tailscale.com/net/stunserver"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// Settings of the central DERP server (stored in the database).
type Settings struct {
	Enabled       bool
	Domain        string
	RegionID      int
	RegionCode    string
	RegionName    string
	STUNPort      int
	VerifyClients bool
	FailOpen      bool
	IPv4          string
	IPv6          string
}

// AdmitFunc decides whether a node key may use the relay.
type AdmitFunc func(nodeKey string, src netip.Addr) bool

// Service is the embedded DERP/STUN server.
type Service struct {
	dataDir string
	log     *slog.Logger
	admit   AdmitFunc

	internalURL string
	internalSrv *http.Server

	allowed atomic.Int64
	denied  atomic.Int64

	mu         sync.Mutex
	cfg        Settings
	srv        *derpserver.Server
	handler    http.Handler
	stunCancel context.CancelFunc
	stunErr    string
	started    time.Time
}

// New creates the service and starts the internal admission endpoint on
// loopback (never exposed).
func New(dataDir string, log *slog.Logger, admit AdmitFunc) (*Service, error) {
	s := &Service{dataDir: dataDir, log: log, admit: admit}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	secretPath := "/admit/" + randomHex(16)
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+secretPath, s.handleAdmit)
	s.internalSrv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go s.internalSrv.Serve(ln)
	s.internalURL = "http://" + ln.Addr().String() + secretPath
	return s, nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func (s *Service) handleAdmit(w http.ResponseWriter, r *http.Request) {
	var req tailcfg.DERPAdmitClientRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ok := s.admit(req.NodePublic.String(), req.Source)
	if ok {
		s.allowed.Add(1)
	} else {
		s.denied.Add(1)
		s.log.Info("derp: client rejected", "node_key", req.NodePublic.ShortString(), "src", req.Source)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tailcfg.DERPAdmitClientResponse{Allow: ok})
}

func (s *Service) privateKey() (key.NodePrivate, error) {
	dir := filepath.Join(s.dataDir, "derp")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return key.NodePrivate{}, err
	}
	path := filepath.Join(dir, "derp_private.key")
	if b, err := os.ReadFile(path); err == nil {
		var k key.NodePrivate
		if err := k.UnmarshalText([]byte(strings.TrimSpace(string(b)))); err != nil {
			return key.NodePrivate{}, fmt.Errorf("parsing %s: %w", path, err)
		}
		return k, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return key.NodePrivate{}, err
	}
	k := key.NewNode()
	t, err := k.MarshalText()
	if err != nil {
		return key.NodePrivate{}, err
	}
	if err := os.WriteFile(path, append(t, '\n'), 0o600); err != nil {
		return key.NodePrivate{}, err
	}
	return k, nil
}

// Apply (re)configures the server. Changing verification settings
// restarts the relay, which makes clients reconnect.
func (s *Service) Apply(cfg Settings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.cfg
	s.cfg = cfg
	if !cfg.Enabled {
		s.stopLocked()
		return nil
	}
	needRelay := s.srv == nil || old.VerifyClients != cfg.VerifyClients || old.FailOpen != cfg.FailOpen
	if needRelay {
		if s.srv != nil {
			s.srv.Close()
			s.srv = nil
		}
		pk, err := s.privateKey()
		if err != nil {
			return err
		}
		srv := derpserver.New(pk, func(format string, args ...any) {
			s.log.Debug(fmt.Sprintf(format, args...), "component", "derp")
		})
		if cfg.VerifyClients {
			srv.SetVerifyClientURL(s.internalURL)
			srv.SetVerifyClientURLFailOpen(cfg.FailOpen)
		}
		h := derpserver.Handler(srv)
		h = derpserver.AddWebSocketSupport(srv, h)
		s.srv, s.handler = srv, h
		s.started = time.Now()
	}
	if s.stunCancel == nil || old.STUNPort != cfg.STUNPort {
		if s.stunCancel != nil {
			s.stunCancel()
			s.stunCancel = nil
		}
		s.stunErr = ""
		if cfg.STUNPort > 0 {
			ctx, cancel := context.WithCancel(context.Background())
			ss := stunserver.New(ctx)
			if err := ss.Listen(":" + strconv.Itoa(cfg.STUNPort)); err != nil {
				cancel()
				s.stunErr = err.Error()
				s.log.Warn("STUN listen failed", "port", cfg.STUNPort, "err", err)
			} else {
				s.stunCancel = cancel
				go ss.Serve()
			}
		}
	}
	return nil
}

func (s *Service) stopLocked() {
	if s.srv != nil {
		s.srv.Close()
		s.srv, s.handler = nil, nil
	}
	if s.stunCancel != nil {
		s.stunCancel()
		s.stunCancel = nil
	}
}

// Close stops everything.
func (s *Service) Close() {
	s.mu.Lock()
	s.stopLocked()
	s.mu.Unlock()
	s.internalSrv.Close()
}

// Settings returns the active settings.
func (s *Service) Settings() Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg
}

// ServeHTTP serves the DERP domain.
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/derp/probe", "/derp/latency-check":
		derpserver.ProbeHandler(w, r)
		return
	case "/generate_204":
		derpserver.ServeNoContent(w, r)
		return
	case "/robots.txt":
		io.WriteString(w, "User-agent: *\nDisallow: /\n")
		return
	case "/derp":
		s.mu.Lock()
		h := s.handler
		s.mu.Unlock()
		if h == nil {
			http.Error(w, "derp server disabled", http.StatusNotFound)
			return
		}
		h.ServeHTTP(w, r)
		return
	case "/":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		io.WriteString(w, "DERP relay\n")
		return
	}
	http.NotFound(w, r)
}

// AddMetaCert appends the DERP meta certificate to a TLS certificate so
// clients can skip a round trip when connecting.
func (s *Service) AddMetaCert(cert *tls.Certificate) *tls.Certificate {
	s.mu.Lock()
	srv := s.srv
	s.mu.Unlock()
	if srv == nil || cert == nil {
		return cert
	}
	c := *cert
	c.Certificate = append(append([][]byte(nil), cert.Certificate...), srv.MetaCert())
	return &c
}

// Stats summarizes the relay state.
type Stats struct {
	Running       bool
	Since         time.Time
	PublicKey     string
	Connections   int64
	HomeConns     int64
	Accepts       int64
	BytesReceived int64
	BytesSent     int64
	PacketsSent   int64
	PacketsRecv   int64
	AdmitAllowed  int64
	AdmitDenied   int64
	STUNRunning   bool
	STUNError     string
}

// Stats returns live statistics.
func (s *Service) Stats() Stats {
	s.mu.Lock()
	srv := s.srv
	st := Stats{Running: srv != nil, Since: s.started, STUNRunning: s.stunCancel != nil, STUNError: s.stunErr}
	s.mu.Unlock()
	st.AdmitAllowed, st.AdmitDenied = s.allowed.Load(), s.denied.Load()
	if srv == nil {
		return st
	}
	st.PublicKey = srv.PublicKey().String()
	var m map[string]any
	if err := json.Unmarshal([]byte(srv.ExpVar(false).String()), &m); err == nil {
		num := func(k string) int64 {
			switch v := m[k].(type) {
			case float64:
				return int64(v)
			case json.Number:
				n, _ := v.Int64()
				return n
			}
			return 0
		}
		st.Connections = num("gauge_current_connections")
		st.HomeConns = num("gauge_current_home_connections")
		st.Accepts = num("accepts")
		st.BytesReceived = num("bytes_received")
		st.BytesSent = num("bytes_sent")
		st.PacketsSent = num("packets_sent")
		st.PacketsRecv = num("packets_received")
	}
	return st
}

// Client is one connection to the relay.
type Client struct {
	Key         string    `json:"key"`
	Remote      string    `json:"remote"`
	ConnectedAt time.Time `json:"connectedAt"`
	Home        bool      `json:"home"`
	RxBytes     uint64    `json:"rxBytes"`
	TxBytes     uint64    `json:"txBytes"`
	RxPkts      uint64    `json:"rxPkts"`
	TxPkts      uint64    `json:"txPkts"`
	Version     int       `json:"version"`
}

// Clients lists the currently connected clients with traffic counters.
func (s *Service) Clients(limit int) ([]Client, error) {
	s.mu.Lock()
	srv := s.srv
	s.mu.Unlock()
	if srv == nil {
		return nil, nil
	}
	var out []Client
	q := url.Values{}
	q.Set("all", "")
	q.Set("format", "json")
	q.Set("sort", "key")
	q.Set("limit", "500")
	next := "/debug/clients/?" + q.Encode()
	for i := 0; i < 50 && next != "" && len(out) < limit; i++ {
		req := httptest.NewRequest(http.MethodGet, next, nil)
		rec := httptest.NewRecorder()
		srv.ServeDebugClients(rec, req)
		if rec.Code != http.StatusOK {
			return out, fmt.Errorf("derp clients: %s", strings.TrimSpace(rec.Body.String()))
		}
		var page struct {
			Next    string   `json:"next"`
			Clients []Client `json:"clients"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
			return out, err
		}
		out = append(out, page.Clients...)
		next = ""
		if page.Next != "" {
			if u, err := url.Parse(page.Next); err == nil {
				next = "/debug/clients/?" + u.RawQuery
			}
		}
	}
	return out, nil
}
