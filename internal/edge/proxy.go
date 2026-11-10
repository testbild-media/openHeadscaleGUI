package edge

import (
	"context"
	"crypto/tls"
	"html/template"
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
		rp.ServeHTTP(w, r)
	})
}

// ForwardTarget configures an HTTP forward.
type ForwardTarget struct {
	ID           int64
	Domain       string
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
