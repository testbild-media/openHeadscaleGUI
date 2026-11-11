package edge

import (
	"bufio"
	"context"
	"crypto/tls"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/testbild-media/openHeadscaleGUI/internal/forward"
)

// blockedHeadscalePaths must not be reachable from the internet.
var blockedHeadscalePaths = []string{"/api", "/swagger", "/verify", "/metrics", "/debug", "/version"}

// RegisterFunc handles an interactive registration page request.
type RegisterFunc func(w http.ResponseWriter, r *http.Request, authID string)

// HeadscaleProxy returns a reverse proxy to a headscale instance on
// loopback. GET /register/{auth_id} is intercepted.
func HeadscaleProxy(port int, onRegister RegisterFunc, log *slog.Logger) http.Handler {
	target := &url.URL{Scheme: "http", Host: "127.0.0.1:" + strconv.Itoa(port)}
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host
			ip := ClientIP(pr.In)
			if ip.IsValid() {
				pr.Out.Header.Set("X-Forwarded-For", ip.String())
				pr.Out.Header.Set("X-Real-Ip", ip.String())
			}
			pr.Out.Header.Set("X-Forwarded-Proto", "https")
			pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
		},
		// Map responses are streamed long-polls: flush immediately.
		FlushInterval: -1,
		Transport: &http.Transport{
			DialContext:         (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			MaxIdleConns:        200,
			MaxIdleConnsPerHost: 200,
			IdleConnTimeout:     90 * time.Second,
			DisableCompression:  true,
		},
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelDebug),
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, "control server unavailable", http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		for _, b := range blockedHeadscalePaths {
			if p == b || strings.HasPrefix(p, b+"/") {
				http.NotFound(w, r)
				return
			}
		}
		if r.Method == http.MethodGet && strings.HasPrefix(p, "/register/") && !strings.HasPrefix(p, "/register/confirm/") && onRegister != nil {
			onRegister(w, r, strings.TrimPrefix(p, "/register/"))
			return
		}
		if isUpgrade(r) {
			proxyUpgrade(w, r, target.Host, log)
			return
		}
		rp.ServeHTTP(w, r)
	})
}

func isUpgrade(r *http.Request) bool {
	if r.Header.Get("Upgrade") == "" {
		return false
	}
	for _, v := range r.Header.Values("Connection") {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), "upgrade") {
				return true
			}
		}
	}
	return false
}

// proxyUpgrade forwards an HTTP/1.1 upgrade (headscale's /ts2021 Noise
// protocol or WebSocket) to backend. Unlike httputil.ReverseProxy, which
// only half-closes the client side when the backend goes away, both
// connections are fully closed as soon as either side ends, so clients
// reconnect immediately after a headscale restart.
func proxyUpgrade(w http.ResponseWriter, r *http.Request, backend string, log *slog.Logger) {
	if r.ProtoMajor != 1 {
		http.Error(w, "upgrade requires HTTP/1.1", http.StatusHTTPVersionNotSupported)
		return
	}
	bc, err := net.DialTimeout("tcp", backend, 5*time.Second)
	if err != nil {
		http.Error(w, "control server unavailable", http.StatusBadGateway)
		return
	}
	out := r.Clone(r.Context())
	out.URL = &url.URL{Path: r.URL.Path, RawPath: r.URL.RawPath, RawQuery: r.URL.RawQuery}
	out.RequestURI = ""
	out.Host = r.Host
	ip := ClientIP(r)
	out.Header.Del("X-Forwarded-For")
	if ip.IsValid() {
		out.Header.Set("X-Forwarded-For", ip.String())
		out.Header.Set("X-Real-Ip", ip.String())
	}
	out.Header.Set("X-Forwarded-Proto", "https")
	out.Header.Set("X-Forwarded-Host", r.Host)
	_ = bc.SetDeadline(time.Now().Add(30 * time.Second))
	if err := out.Write(bc); err != nil {
		bc.Close()
		http.Error(w, "control server unavailable", http.StatusBadGateway)
		return
	}
	br := bufio.NewReader(bc)
	res, err := http.ReadResponse(br, out)
	if err != nil {
		bc.Close()
		http.Error(w, "control server unavailable", http.StatusBadGateway)
		return
	}
	if res.StatusCode != http.StatusSwitchingProtocols {
		defer bc.Close()
		defer res.Body.Close()
		for k, vv := range res.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(res.StatusCode)
		_, _ = io.Copy(w, io.LimitReader(res.Body, 1<<20))
		return
	}
	_ = bc.SetDeadline(time.Time{})
	cc, cbrw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		bc.Close()
		log.Debug("hijack failed", "err", err)
		return
	}
	_ = cc.SetDeadline(time.Time{})
	if err := res.Write(cc); err != nil {
		cc.Close()
		bc.Close()
		return
	}
	done := make(chan struct{}, 2)
	go func() {
		// client -> backend (including bytes the server already buffered)
		_, _ = io.Copy(bc, cbrw.Reader)
		done <- struct{}{}
	}()
	go func() {
		// backend -> client (including early data buffered after the 101)
		_, _ = io.Copy(cc, br)
		done <- struct{}{}
	}()
	<-done
	cc.Close()
	bc.Close()
	<-done
}

// ForwardTarget configures an HTTP forward.
type ForwardTarget struct {
	ID     int64
	Domain string
	// PublicURL is the public base URL (scheme://domain[:port]); redirects of
	// the target to itself are rewritten to it.
	PublicURL    string
	UpstreamTLS  bool
	Insecure     bool
	PreserveHost bool
	Allow        []netip.Prefix
	BasicUser    string
	// CheckBasic validates basic-auth credentials (nil = no auth).
	CheckBasic func(user, pass string) bool
	// Target returns the current host:port inside the tailnet.
	Target func() (string, error)
	Dial   func(ctx context.Context, network, addr string) (net.Conn, error)
	C      *forward.Counters
}

var errorPage = template.Must(template.New("e").Parse(`<!doctype html><html lang="de"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{{.Code}}</title>
<style>body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;display:grid;place-items:center;min-height:100vh;margin:0}
main{max-width:32rem;padding:2rem;text-align:center}h1{font-size:3rem;margin:0}p{color:#94a3b8}</style>
<main><h1>{{.Code}}</h1><p>{{.Msg}}</p></main></html>`))

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	errorPage.Execute(w, map[string]any{"Code": code, "Msg": msg})
}

// ForwardProxy returns the handler for an HTTP forward.
func ForwardProxy(ft ForwardTarget, log *slog.Logger) http.Handler {
	scheme := "http"
	if ft.UpstreamTLS {
		scheme = "https"
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			addr, err := ft.Target()
			if err != nil {
				return nil, err
			}
			dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			c, err := ft.Dial(dctx, "tcp", addr)
			if err != nil {
				return nil, err
			}
			return &forward.CountingConn{Conn: c, C: ft.C}, nil
		},
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   64,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		ForceAttemptHTTP2:     true,
	}
	if ft.UpstreamTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: ft.Insecure, MinVersion: tls.VersionTLS12}
		if ft.PreserveHost {
			tr.TLSClientConfig.ServerName = ft.Domain
		}
	}
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			host := "upstream"
			if t, err := ft.Target(); err == nil {
				host = t
			}
			pr.SetURL(&url.URL{Scheme: scheme, Host: host})
			if ft.PreserveHost {
				pr.Out.Host = pr.In.Host
			}
			ip := ClientIP(pr.In)
			if ip.IsValid() {
				pr.Out.Header.Set("X-Forwarded-For", ip.String())
				pr.Out.Header.Set("X-Real-Ip", ip.String())
			}
			pr.Out.Header.Set("X-Forwarded-Proto", "https")
			pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
			if ft.CheckBasic != nil {
				pr.Out.Header.Del("Authorization")
			}
		},
		Transport:     tr,
		FlushInterval: 100 * time.Millisecond,
		ErrorLog:      slog.NewLogLogger(log.Handler(), slog.LevelDebug),
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			ft.C.RecordError(err)
			writeError(w, http.StatusBadGateway, "Das Ziel im VPN ist derzeit nicht erreichbar.")
		},
		ModifyResponse: func(resp *http.Response) error {
			if ft.PublicURL == "" || resp.Request == nil {
				return nil
			}
			for _, h := range []string{"Location", "Content-Location"} {
				if v := resp.Header.Get(h); v != "" {
					if nv, ok := RewriteLocation(v, resp.Request.URL, ft.Domain, ft.PublicURL); ok {
						resp.Header.Set(h, nv)
					}
				}
			}
			return nil
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !forward.Allowed(ft.Allow, ClientIP(r)) {
			writeError(w, http.StatusForbidden, "Zugriff von dieser Adresse nicht erlaubt.")
			return
		}
		if ft.CheckBasic != nil {
			u, p, ok := r.BasicAuth()
			if !ok || !ft.CheckBasic(u, p) {
				w.Header().Set("WWW-Authenticate", `Basic realm="`+ft.Domain+`", charset="UTF-8"`)
				writeError(w, http.StatusUnauthorized, "Anmeldung erforderlich.")
				return
			}
		}
		ft.C.Active.Add(1)
		ft.C.Total.Add(1)
		defer ft.C.Active.Add(-1)
		rp.ServeHTTP(w, r)
	})
}

// RewriteLocation maps a redirect of the target to itself onto the public
// URL, like nginx' "proxy_redirect default": absolute URLs pointing at the
// upstream address (host and port) or at the public domain with any scheme
// or port (e.g. the target's own HTTPS port) keep path, query and fragment
// but get the public scheme and host. Relative URLs and other hosts are left
// alone. It reports whether the value changed.
func RewriteLocation(loc string, upstream *url.URL, domain, public string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(loc))
	if err != nil || u.Host == "" || u.User != nil {
		return "", false
	}
	if u.Scheme != "" && u.Scheme != "http" && u.Scheme != "https" {
		return "", false
	}
	pub, err := url.Parse(public)
	if err != nil || pub.Host == "" {
		return "", false
	}
	host := u.Hostname()
	match := domain != "" && strings.EqualFold(host, strings.TrimSuffix(domain, "."))
	if !match && upstream != nil && upstream.Host != "" {
		scheme := u.Scheme
		if scheme == "" {
			scheme = upstream.Scheme
		}
		match = strings.EqualFold(host, upstream.Hostname()) && portOf(u.Port(), scheme) == portOf(upstream.Port(), upstream.Scheme)
	}
	if !match {
		return "", false
	}
	u.Scheme, u.Host = pub.Scheme, pub.Host
	out := u.String()
	return out, out != loc
}

func portOf(port, scheme string) string {
	if port != "" {
		return port
	}
	if scheme == "https" {
		return "443"
	}
	return "80"
}
