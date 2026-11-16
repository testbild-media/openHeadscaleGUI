package forward

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// A rule with its own listener, dialer and client check (as used by
// bridges between instances).
func TestRuleCustomListenerAndAdmit(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	var admit atomic.Bool
	admit.Store(true)
	type bound struct {
		id   int64
		addr string
	}
	addrs := make(chan bound, 4)
	reg := NewRegistry()
	m := NewManager(func(context.Context, int64, string, string) (net.Conn, error) {
		t.Error("default dialer used")
		return nil, io.EOF
	}, reg, slog.New(slog.NewTextHandler(io.Discard, nil)), "")
	defer m.StopAll()
	rule := func(id int64, scope string) Rule {
		return Rule{ID: id, Proto: "tcp", Port: 2201, Scope: scope, Version: 1,
			Target: func() (string, error) { return echo.Addr().String(), nil },
			Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
			ListenTCP: func() (net.Listener, error) {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err == nil {
					addrs <- bound{id, ln.Addr().String()}
				}
				return ln, err
			},
			Admit: func(ip netip.Addr) bool { return admit.Load() && ip.IsLoopback() },
		}
	}
	// same port number in two scopes: two independent listeners
	m.Sync([]Rule{rule(1, "inst:1/"), rule(2, "inst:2/")})
	byID := map[int64]string{}
	for i := 0; i < 2; i++ {
		b := <-addrs
		byID[b.id] = b.addr
	}
	a1, a2 := byID[1], byID[2]
	if a1 == "" || a2 == "" || a1 == a2 {
		t.Fatalf("scopes share a listener: %v", byID)
	}
	roundtrip := func(addr string) (string, error) {
		c, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			return "", err
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Write([]byte("ping\n")); err != nil {
			return "", err
		}
		return bufio.NewReader(c).ReadString('\n')
	}
	if got, err := roundtrip(a1); err != nil || got != "ping\n" {
		t.Fatalf("admitted client: %q %v", got, err)
	}
	admit.Store(false)
	if got, err := roundtrip(a2); err == nil && got != "" {
		t.Fatalf("rejected client got data: %q", got)
	}
	if reg.Get(1).Total.Load() != 1 || reg.Get(2).Total.Load() != 0 {
		t.Errorf("counters: %d / %d", reg.Get(1).Total.Load(), reg.Get(2).Total.Load())
	}
}
