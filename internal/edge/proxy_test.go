package edge

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestUpgradeClosesClient is a regression test: when the backend of an
// upgraded /ts2021 connection goes away (headscale restart), the client
// connection must be closed so the tailscale client reconnects.
func TestUpgradeClosesClient(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		br := bufio.NewReader(c)
		req, err := http.ReadRequest(br)
		if err != nil || req.Header.Get("Upgrade") != "tailscale-control-protocol" {
			c.Close()
			return
		}
		io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: tailscale-control-protocol\r\nConnection: Upgrade\r\n\r\nhello")
		time.Sleep(100 * time.Millisecond)
		c.Close() // simulate headscale restart
	}()
	port, _ := strconv.Atoi(strings.Split(ln.Addr().String(), ":")[1])
	h := HeadscaleProxy(port, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := httptest.NewServer(h)
	defer srv.Close()

	c, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "POST /ts2021 HTTP/1.1\r\nHost: vpn.example.com\r\nUpgrade: tailscale-control-protocol\r\nConnection: upgrade\r\nContent-Length: 0\r\n\r\n")
	c.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(c)
	res, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status %d", res.StatusCode)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(br, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("early data not forwarded: %q %v", buf, err)
	}
	// The backend closed: the read must end with EOF instead of blocking.
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("expected EOF")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("client connection was not closed after the backend went away")
	}
}

func TestBlockedPaths(t *testing.T) {
	h := HeadscaleProxy(1, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	for _, p := range []string{"/api/v1/node", "/swagger", "/verify", "/metrics"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: got %d", p, rec.Code)
		}
	}
}
