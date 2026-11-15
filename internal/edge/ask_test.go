package edge

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/testbild-media/openHeadscaleGUI/internal/config"
)

type mapRouter map[string]http.Handler

func (m mapRouter) Route(host string) http.Handler { return m[host] }

func TestTLSAsk(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("site")) })
	cfg := &config.Config{TLSMode: config.TLSModeOff, TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")}}
	s := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), mapRouter{"admin.example.com": ok, "nas.example.com": ok}, nil)
	ask := func(remote, domain string, hdr map[string]string) int {
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8480"+TLSAskPath+"?domain="+domain, nil)
		req.RemoteAddr = remote
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		s.handle(rec, req)
		return rec.Code
	}
	for _, c := range []struct {
		remote, domain string
		hdr            map[string]string
		want           int
	}{
		{"127.0.0.1:5000", "nas.example.com", nil, 200},
		{"[::1]:5000", "ADMIN.example.com", nil, 200},
		{"10.0.0.2:5000", "nas.example.com", nil, 200},   // trusted proxy on another host
		{"127.0.0.1:5000", "evil.example.org", nil, 404}, // unknown domain
		{"127.0.0.1:5000", "", nil, 404},
		{"203.0.113.9:5000", "nas.example.com", nil, 404},                                           // not the proxy -> normal routing (unknown host)
		{"127.0.0.1:5000", "nas.example.com", map[string]string{"X-Forwarded-For": "1.2.3.4"}, 404}, // relayed client request
	} {
		if got := ask(c.remote, c.domain, c.hdr); got != c.want {
			t.Errorf("%s ask %q (hdr %v): %d, want %d", c.remote, c.domain, c.hdr, got, c.want)
		}
	}
	// with TLS handled by ohg itself the path is not special
	s2 := New(&config.Config{TLSMode: config.TLSModeACME}, slog.New(slog.NewTextHandler(io.Discard, nil)), mapRouter{}, nil)
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1"+TLSAskPath+"?domain=x", nil)
	req.RemoteAddr = "127.0.0.1:1"
	rec := httptest.NewRecorder()
	s2.handle(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("ask answered in ACME mode: %d", rec.Code)
	}
}
