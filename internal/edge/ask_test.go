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

func TestPlainHTTPViaProxyRedirects(t *testing.T) {
	site := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("site")) })
	cfg := &config.Config{TLSMode: config.TLSModeOff, TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}
	s := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), mapRouter{"admin.example.com": site}, nil)
	do := func(method, remote, proto string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "http://admin.example.com/setup?x=1", nil)
		req.RemoteAddr = remote
		if proto != "" {
			req.Header.Set("X-Forwarded-Proto", proto)
		}
		rec := httptest.NewRecorder()
		s.handle(rec, req)
		return rec
	}
	if rec := do(http.MethodGet, "127.0.0.1:1", "http"); rec.Code != http.StatusMovedPermanently ||
		rec.Header().Get("Location") != "https://admin.example.com/setup?x=1" {
		t.Errorf("plain HTTP via proxy: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if rec := do(http.MethodPost, "127.0.0.1:1", "http"); rec.Code != http.StatusForbidden {
		t.Errorf("POST over plain HTTP via proxy: %d", rec.Code)
	}
	for _, c := range []struct{ remote, proto string }{
		{"127.0.0.1:1", "https"},
		{"127.0.0.1:1", ""},            // proxy without X-Forwarded-Proto
		{"203.0.113.5:1", "http"},      // untrusted sender: header ignored
		{"127.0.0.1:1", "HTTPS, http"}, // first value counts
	} {
		if rec := do(http.MethodGet, c.remote, c.proto); rec.Code != http.StatusOK {
			t.Errorf("%s proto %q: %d, want site", c.remote, c.proto, rec.Code)
		}
	}
}

func TestPlainHTTPRedirectDomainOneHop(t *testing.T) {
	red := RedirectHandler(RedirectTarget{URL: "https://neu.example.org/start", Code: 301, KeepPath: true,
		Allow: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}})
	site := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("site")) })
	router := mapRouter{"alt.example.com": red, "admin.example.com": site}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// ohg directly on port 80: straight to the target, not to https://alt...
	direct := New(&config.Config{TLSMode: config.TLSModeACME, HTTPSAddr: ":443"}, logger, router, nil)
	req := httptest.NewRequest(http.MethodGet, "http://alt.example.com/a?b=1", nil)
	req.RemoteAddr = "203.0.113.5:1"
	rec := httptest.NewRecorder()
	direct.redirect(rec, req)
	if rec.Code != 301 || rec.Header().Get("Location") != "https://neu.example.org/start/a?b=1" {
		t.Errorf("port 80 redirect domain: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	req = httptest.NewRequest(http.MethodGet, "http://admin.example.com/x", nil)
	rec = httptest.NewRecorder()
	direct.redirect(rec, req)
	if rec.Header().Get("Location") != "https://admin.example.com/x" {
		t.Errorf("other domains still go to https first: %q", rec.Header().Get("Location"))
	}
	req = httptest.NewRequest(http.MethodGet, "http://alt.example.com/", nil)
	req.RemoteAddr = "198.51.100.9:1"
	rec = httptest.NewRecorder()
	direct.redirect(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("IP filter of the redirect ignored on port 80: %d", rec.Code)
	}

	// behind a proxy: plain HTTP relayed with X-Forwarded-For of the real client
	proxied := New(&config.Config{TLSMode: config.TLSModeOff, TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}, logger, router, nil)
	req = httptest.NewRequest(http.MethodPost, "http://alt.example.com/form", nil)
	req.RemoteAddr = "127.0.0.1:1"
	req.Header.Set("X-Forwarded-Proto", "http")
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	rec = httptest.NewRecorder()
	proxied.handle(rec, req)
	if rec.Code != 301 || rec.Header().Get("Location") != "https://neu.example.org/start/form" {
		t.Errorf("proxied plain HTTP redirect domain: %d %q", rec.Code, rec.Header().Get("Location"))
	}
}
