// Package forward implements public TCP/UDP port forwarding into tailnets
// and keeps per-forward traffic counters (also used by HTTP forwards).
package forward

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Counters collects traffic statistics of one forward.
type Counters struct {
	BytesIn     atomic.Int64 // client -> target
	BytesOut    atomic.Int64 // target -> client
	Active      atomic.Int64
	Total       atomic.Int64
	Errors      atomic.Int64
	LastError   atomic.Value // string
	LastErrorAt atomic.Int64
}

// RecordError stores the last error.
func (c *Counters) RecordError(err error) {
	c.Errors.Add(1)
	c.LastError.Store(err.Error())
	c.LastErrorAt.Store(time.Now().Unix())
}

// Snapshot is a copy of counter values.
type Snapshot struct {
	BytesIn, BytesOut, Active, Total, Errors int64
	LastError                                string
	LastErrorAt                              int64
}

// Snapshot returns the current values.
func (c *Counters) Snapshot() Snapshot {
	s := Snapshot{
		BytesIn: c.BytesIn.Load(), BytesOut: c.BytesOut.Load(), Active: c.Active.Load(),
		Total: c.Total.Load(), Errors: c.Errors.Load(), LastErrorAt: c.LastErrorAt.Load(),
	}
	if v, ok := c.LastError.Load().(string); ok {
		s.LastError = v
	}
	return s
}

// Registry holds the counters of all forwards.
type Registry struct {
	mu sync.Mutex
	m  map[int64]*Counters
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry { return &Registry{m: map[int64]*Counters{}} }

// Get returns (creating if needed) the counters of a forward.
func (r *Registry) Get(id int64) *Counters {
	r.mu.Lock()
	defer r.mu.Unlock()
	c := r.m[id]
	if c == nil {
		c = &Counters{}
		r.m[id] = c
	}
	return c
}

// Snapshot returns a copy of all counters.
func (r *Registry) Snapshot() map[int64]Snapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[int64]Snapshot, len(r.m))
	for id, c := range r.m {
		out[id] = c.Snapshot()
	}
	return out
}

// Dialer opens a connection inside the tailnet of an instance.
type Dialer func(ctx context.Context, instanceID int64, network, addr string) (net.Conn, error)

// Rule is one TCP or UDP forward.
type Rule struct {
	ID         int64
	InstanceID int64
	Proto      string // "tcp" or "udp"
	Port       int
	Allow      []netip.Prefix
	// Target returns the current "host:port" inside the tailnet.
	Target func() (string, error)
	// Version changes whenever the rule changes (forces a restart).
	Version int64
}

func (r Rule) key() string { return r.Proto + "/" + strconv.Itoa(r.Port) }

// Allowed reports whether ip may use the rule.
func Allowed(allow []netip.Prefix, ip netip.Addr) bool {
	if len(allow) == 0 {
		return true
	}
	ip = ip.Unmap()
	for _, p := range allow {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// Manager runs the TCP/UDP listeners.
type Manager struct {
	dial     Dialer
	reg      *Registry
	log      *slog.Logger
	bindHost string

	mu   sync.Mutex
	runs map[string]*running
}

type running struct {
	rule   Rule
	cancel context.CancelFunc
	done   chan struct{}
	err    atomic.Value
}

// NewManager creates a forwarding manager. bindHost is usually "" (all).
func NewManager(dial Dialer, reg *Registry, log *slog.Logger, bindHost string) *Manager {
	return &Manager{dial: dial, reg: reg, log: log, bindHost: bindHost, runs: map[string]*running{}}
}

// ListenError returns the bind error of a rule (if any).
func (m *Manager) ListenError(proto string, port int) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.runs[proto+"/"+strconv.Itoa(port)]
	if r == nil {
		return ""
	}
	if v, ok := r.err.Load().(string); ok {
		return v
	}
	return ""
}

// Sync makes the running listeners match rules.
func (m *Manager) Sync(rules []Rule) {
	want := map[string]Rule{}
	for _, r := range rules {
		want[r.key()] = r
	}
	m.mu.Lock()
	var stop []*running
	for k, r := range m.runs {
		w, ok := want[k]
		if !ok || w.ID != r.rule.ID || w.Version != r.rule.Version {
			stop = append(stop, r)
			delete(m.runs, k)
		}
	}
	m.mu.Unlock()
	for _, r := range stop {
		r.cancel()
		<-r.done
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, w := range want {
		if _, ok := m.runs[k]; ok {
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		r := &running{rule: w, cancel: cancel, done: make(chan struct{})}
		m.runs[k] = r
		go m.serve(ctx, r)
	}
}

// StopAll stops every listener.
func (m *Manager) StopAll() { m.Sync(nil) }

func (m *Manager) serve(ctx context.Context, r *running) {
	defer close(r.done)
	addr := net.JoinHostPort(m.bindHost, strconv.Itoa(r.rule.Port))
	for ctx.Err() == nil {
		var err error
		if r.rule.Proto == "udp" {
			err = m.serveUDP(ctx, r, addr)
		} else {
			err = m.serveTCP(ctx, r, addr)
		}
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			r.err.Store(err.Error())
			m.log.Warn("forward listener failed", "proto", r.rule.Proto, "port", r.rule.Port, "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Second):
		}
	}
}

const maxConnsPerRule = 512

func (m *Manager) serveTCP(ctx context.Context, r *running, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	r.err.Store("")
	go func() { <-ctx.Done(); ln.Close() }()
	c := m.reg.Get(r.rule.ID)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		ap, _ := netip.ParseAddrPort(conn.RemoteAddr().String())
		if !Allowed(r.rule.Allow, ap.Addr()) {
			conn.Close()
			continue
		}
		if c.Active.Load() >= maxConnsPerRule {
			conn.Close()
			continue
		}
		go m.handleTCP(ctx, r, conn, c)
	}
}

func (m *Manager) handleTCP(ctx context.Context, r *running, conn net.Conn, c *Counters) {
	defer conn.Close()
	c.Active.Add(1)
	c.Total.Add(1)
	defer c.Active.Add(-1)
	target, err := r.rule.Target()
	if err != nil {
		c.RecordError(err)
		return
	}
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	up, err := m.dial(dctx, r.rule.InstanceID, "tcp", target)
	cancel()
	if err != nil {
		c.RecordError(fmt.Errorf("dial %s: %w", target, err))
		return
	}
	defer up.Close()
	Pipe(ctx, conn, up, c)
}

// Pipe copies data in both directions until one side closes.
func Pipe(ctx context.Context, client, upstream net.Conn, c *Counters) {
	done := make(chan struct{}, 2)
	go func() {
		n, _ := io.Copy(upstream, client)
		c.BytesIn.Add(n)
		if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			upstream.Close()
		}
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(client, upstream)
		c.BytesOut.Add(n)
		if cw, ok := client.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			client.Close()
		}
		done <- struct{}{}
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
	// give the other direction a moment to drain, then close both
	select {
	case <-done:
	case <-time.After(30 * time.Second):
	case <-ctx.Done():
	}
	client.Close()
	upstream.Close()
}

const (
	udpIdleTimeout    = 2 * time.Minute
	maxUDPSessions    = 1024
	maxUDPPacketBytes = 65535
)

type udpSession struct {
	up       net.Conn
	lastSeen atomic.Int64
}

func (m *Manager) serveUDP(ctx context.Context, r *running, addr string) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	r.err.Store("")
	defer pc.Close()
	go func() { <-ctx.Done(); pc.Close() }()
	c := m.reg.Get(r.rule.ID)
	var mu sync.Mutex
	sessions := map[string]*udpSession{}
	defer func() {
		mu.Lock()
		for _, s := range sessions {
			s.up.Close()
		}
		mu.Unlock()
	}()
	// idle reaper
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			cut := time.Now().Add(-udpIdleTimeout).Unix()
			mu.Lock()
			for k, s := range sessions {
				if s.lastSeen.Load() < cut {
					s.up.Close()
					delete(sessions, k)
					c.Active.Add(-1)
				}
			}
			mu.Unlock()
		}
	}()
	buf := make([]byte, maxUDPPacketBytes)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		ap, _ := netip.ParseAddrPort(from.String())
		if !Allowed(r.rule.Allow, ap.Addr()) {
			continue
		}
		key := from.String()
		mu.Lock()
		s := sessions[key]
		if s == nil {
			if len(sessions) >= maxUDPSessions {
				mu.Unlock()
				continue
			}
			target, err := r.rule.Target()
			if err != nil {
				mu.Unlock()
				c.RecordError(err)
				continue
			}
			dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			up, err := m.dial(dctx, r.rule.InstanceID, "udp", target)
			cancel()
			if err != nil {
				mu.Unlock()
				c.RecordError(fmt.Errorf("dial %s: %w", target, err))
				continue
			}
			s = &udpSession{up: up}
			sessions[key] = s
			c.Active.Add(1)
			c.Total.Add(1)
			go func(s *udpSession, from net.Addr, key string) {
				b := make([]byte, maxUDPPacketBytes)
				for {
					s.up.SetReadDeadline(time.Now().Add(udpIdleTimeout))
					n, err := s.up.Read(b)
					if err != nil {
						mu.Lock()
						if sessions[key] == s {
							delete(sessions, key)
							c.Active.Add(-1)
						}
						mu.Unlock()
						s.up.Close()
						return
					}
					s.lastSeen.Store(time.Now().Unix())
					if _, err := pc.WriteTo(b[:n], from); err == nil {
						c.BytesOut.Add(int64(n))
					}
				}
			}(s, from, key)
		}
		mu.Unlock()
		s.lastSeen.Store(time.Now().Unix())
		if _, err := s.up.Write(buf[:n]); err == nil {
			c.BytesIn.Add(int64(n))
		}
	}
}

// CountingConn wraps a net.Conn and counts bytes.
type CountingConn struct {
	net.Conn
	C *Counters
}

// Read counts bytes received from the upstream (sent to the client).
func (cc *CountingConn) Read(b []byte) (int, error) {
	n, err := cc.Conn.Read(b)
	cc.C.BytesOut.Add(int64(n))
	return n, err
}

// Write counts bytes sent to the upstream (received from the client).
func (cc *CountingConn) Write(b []byte) (int, error) {
	n, err := cc.Conn.Write(b)
	cc.C.BytesIn.Add(int64(n))
	return n, err
}
