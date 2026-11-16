package edge

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/testbild-media/openHeadscaleGUI/internal/forward"
)

func TestRewriteLocation(t *testing.T) {
	up := &url.URL{Scheme: "http", Host: "100.100.0.7:8000"}
	upTLS := &url.URL{Scheme: "https", Host: "100.100.0.7:443"}
	const dom, pub = "speed.example.com", "https://speed.example.com"
	for _, c := range []struct {
		loc  string
		up   *url.URL
		want string // "" = unchanged
	}{
		{"http://100.100.0.7:8000/login?x=1#f", up, "https://speed.example.com/login?x=1#f"},
		{"//100.100.0.7:8000/a", up, "https://speed.example.com/a"},
		{"https://100.100.0.7/a", upTLS, "https://speed.example.com/a"},
		{"https://speed.example.com:3001/", up, "https://speed.example.com/"},
		{"http://SPEED.example.com/x", up, "https://speed.example.com/x"},
		{"https://speed.example.com/x", up, ""},      // already public
		{"/relative/path", up, ""},                   // relative
		{"http://100.100.0.7:8443/", up, ""},         // other service on the device
		{"https://accounts.example.org/cb", up, ""},  // foreign host (e.g. OAuth)
		{"http://user:pw@100.100.0.7:8000/", up, ""}, // userinfo is never rewritten
		{"ftp://speed.example.com/file", up, ""},     // other scheme
	} {
		got, ok := RewriteLocation(c.loc, c.up, dom, pub)
		if c.want == "" {
			if ok {
				t.Errorf("%s: rewritten to %s, want unchanged", c.loc, got)
			}
			continue
		}
		if !ok || got != c.want {
			t.Errorf("%s: got %q (%v), want %q", c.loc, got, ok, c.want)
		}
	}
	// dev mode: public URL with port
	if got, _ := RewriteLocation("http://100.100.0.7:8000/a", up, dom, "http://speed.example.com:18480"); got != "http://speed.example.com:18480/a" {
		t.Errorf("dev public URL: %s", got)
	}
}

func TestForwardProxyRewritesRedirect(t *testing.T) {
	var upHost string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/self":
			http.Redirect(w, r, "http://"+upHost+"/login", http.StatusFound)
		case "/tlsport":
			http.Redirect(w, r, "https://"+r.Host+":3001/", http.StatusMovedPermanently)
		case "/foreign":
			http.Redirect(w, r, "https://idp.example.org/auth", http.StatusFound)
		}
	}))
	defer backend.Close()
	upHost = backend.Listener.Addr().String()
	ft := ForwardTarget{
		ID: 1, Domain: "speed.example.com", PublicURL: "https://speed.example.com", PreserveHost: true,
		Target: func() (string, error) { return upHost, nil },
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
		C: &forward.Counters{},
	}
	h := ForwardProxy(ft, slog.New(slog.NewTextHandler(io.Discard, nil)))
	for path, want := range map[string]string{
		"/self":    "https://speed.example.com/login",
		"/tlsport": "https://speed.example.com/",
		"/foreign": "https://idp.example.org/auth",
	} {
		req := httptest.NewRequest(http.MethodGet, "https://speed.example.com"+path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if got := rec.Header().Get("Location"); got != want {
			t.Errorf("%s: Location %q, want %q (status %d, body %s)", path, got, want, rec.Code, strings.TrimSpace(rec.Body.String()))
		}
	}
}

func TestForwardLoopDetected(t *testing.T) {
	var calls int
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Via") != viaOHG {
			t.Errorf("Via header not set: %q", r.Header.Get("Via"))
		}
	}))
	defer backend.Close()
	ft := ForwardTarget{ID: 1, Domain: "os.example.com", PublicURL: "https://os.example.com",
		Target: func() (string, error) { return backend.Listener.Addr().String(), nil },
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
		C: &forward.Counters{}}
	h := ForwardProxy(ft, slog.New(slog.NewTextHandler(io.Discard, nil)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://os.example.com/", nil))
	if rec.Code != 200 || calls != 1 {
		t.Fatalf("first hop: %d calls=%d", rec.Code, calls)
	}
	req := httptest.NewRequest(http.MethodGet, "https://os.example.com/", nil)
	req.Header.Set("Via", "1.1 caddy, 1.1 ohg")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusLoopDetected || calls != 1 {
		t.Errorf("loop not detected: %d calls=%d", rec.Code, calls)
	}
}
