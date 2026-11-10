// Package edge is the public facing HTTP(S) server. It terminates TLS for
// all managed domains (ACME), routes requests by host and implements the
// reverse proxies for headscale instances and HTTP forwards.
package edge

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/testbild-media/openHeadscaleGUI/internal/config"
)

// Router maps a host name to the handler serving it.
type Router interface {
	// Route returns the handler for host or nil if the host is unknown.
	Route(host string) http.Handler
}

// CertHook can modify the certificate served for a host (used to append
// the DERP meta certificate).
type CertHook func(host string, cert *tls.Certificate) *tls.Certificate

// Server is the edge server.
type Server struct {
	cfg      *config.Config
	log      *slog.Logger
	router   Router
	certHook CertHook

	acmeMgr *autocert.Manager

	selfMu    sync.Mutex
	selfCerts map[string]*tls.Certificate

	httpSrv  *http.Server
	httpsSrv *http.Server
}

// New creates the edge server.
func New(cfg *config.Config, log *slog.Logger, router Router, hook CertHook) *Server {
	s := &Server{cfg: cfg, log: log, router: router, certHook: hook, selfCerts: map[string]*tls.Certificate{}}
	if cfg.TLSMode == config.TLSModeACME {
		s.acmeMgr = &autocert.Manager{
			Prompt: autocert.AcceptTOS,
			Cache:  autocert.DirCache(filepath.Join(cfg.DataDir, "acme")),
			Email:  cfg.ACMEEmail,
			HostPolicy: func(ctx context.Context, host string) error {
				if s.router.Route(strings.ToLower(host)) == nil {
					return fmt.Errorf("host %q not configured", host)
				}
				return nil
			},
			Client:      &acme.Client{DirectoryURL: cfg.ACMEDirectory},
			RenewBefore: 30 * 24 * time.Hour,
		}
	}
	return s
}

type ctxKey int

const clientIPKey ctxKey = 1

// ClientIP returns the client address determined by the edge.
func ClientIP(r *http.Request) netip.Addr {
	if v, ok := r.Context().Value(clientIPKey).(netip.Addr); ok {
		return v
	}
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

func (s *Server) trusted(a netip.Addr) bool {
	for _, p := range s.cfg.TrustedProxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// resolveClientIP honours X-Forwarded-For only from trusted proxies and
// picks the right-most untrusted address.
func (s *Server) resolveClientIP(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	remote := ap.Addr().Unmap()
	if len(s.cfg.TrustedProxies) == 0 || !s.trusted(remote) {
		return remote
	}
	parts := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil {
			break
		}
		a = a.Unmap()
		if !s.trusted(a) {
			return a
		}
	}
	return remote
}

// HostOnly lowercases and strips the port of a Host header.
func HostOnly(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.TrimSuffix(h, ".")
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	ip := s.resolveClientIP(r)
	r = r.WithContext(context.WithValue(r.Context(), clientIPKey, ip))
	host := HostOnly(r.Host)
	if r.TLS != nil && r.TLS.ServerName != "" && !strings.EqualFold(strings.TrimSuffix(r.TLS.ServerName, "."), host) {
		// Prevent domain fronting between managed domains.
		http.Error(w, "misdirected request", http.StatusMisdirectedRequest)
		return
	}
	h := s.router.Route(host)
	if h == nil {
		http.NotFound(w, r)
		return
	}
	h.ServeHTTP(w, r)
}

func (s *Server) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))
	if name == "" {
		return nil, errors.New("missing server name")
	}
	if s.router.Route(name) == nil {
		return nil, fmt.Errorf("unknown host %q", name)
	}
	var cert *tls.Certificate
	var err error
	switch s.cfg.TLSMode {
	case config.TLSModeACME:
		cert, err = s.acmeMgr.GetCertificate(hello)
		// ACME TLS-ALPN challenge certificates must not be modified.
		for _, p := range hello.SupportedProtos {
			if p == acme.ALPNProto {
				return cert, err
			}
		}
	default:
		cert, err = s.selfSigned(name)
	}
	if err != nil {
		return nil, err
	}
	if s.certHook != nil {
		cert = s.certHook(name, cert)
	}
	return cert, nil
}

func (s *Server) selfSigned(host string) (*tls.Certificate, error) {
	s.selfMu.Lock()
	defer s.selfMu.Unlock()
	if c := s.selfCerts[host]; c != nil {
		return c, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host, Organization: []string{"OpenHeadscaleGUI self-signed"}},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	c := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	s.selfCerts[host] = c
	return c, nil
}

// redirect sends known hosts on port 80 to HTTPS.
func (s *Server) redirect(w http.ResponseWriter, r *http.Request) {
	host := HostOnly(r.Host)
	if s.router.Route(host) == nil || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
		http.NotFound(w, r)
		return
	}
	target := s.cfg.PublicURL(host) + r.URL.RequestURI()
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}

// Start opens the listeners.
func (s *Server) Start() error {
	handler := http.HandlerFunc(s.handle)
	errLog := slog.NewLogLogger(s.log.Handler(), slog.LevelDebug)
	if s.cfg.TLSMode == config.TLSModeOff {
		s.httpSrv = &http.Server{
			Addr:              s.cfg.HTTPAddr,
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
			MaxHeaderBytes:    64 << 10,
			ErrorLog:          errLog,
		}
		ln, err := net.Listen("tcp", s.cfg.HTTPAddr)
		if err != nil {
			return err
		}
		go s.httpSrv.Serve(ln)
		s.log.Info("edge listening (plain HTTP, TLS off)", "addr", s.cfg.HTTPAddr)
		return nil
	}

	var tlsCfg *tls.Config
	if s.acmeMgr != nil {
		tlsCfg = s.acmeMgr.TLSConfig()
	} else {
		tlsCfg = &tls.Config{NextProtos: []string{"h2", "http/1.1"}}
	}
	tlsCfg.GetCertificate = s.getCertificate
	tlsCfg.MinVersion = tls.VersionTLS12
	tlsCfg.CipherSuites = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}

	s.httpsSrv = &http.Server{
		Addr:              s.cfg.HTTPSAddr,
		Handler:           handler,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          errLog,
	}
	ln, err := net.Listen("tcp", s.cfg.HTTPSAddr)
	if err != nil {
		return err
	}
	go s.httpsSrv.Serve(tls.NewListener(ln, tlsCfg))

	var httpHandler http.Handler = http.HandlerFunc(s.redirect)
	if s.acmeMgr != nil {
		httpHandler = s.acmeMgr.HTTPHandler(httpHandler)
	}
	s.httpSrv = &http.Server{
		Addr:              s.cfg.HTTPAddr,
		Handler:           httpHandler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
		ErrorLog:          errLog,
	}
	ln80, err := net.Listen("tcp", s.cfg.HTTPAddr)
	if err != nil {
		s.log.Warn("HTTP listener failed (ACME HTTP-01 and redirects unavailable)", "addr", s.cfg.HTTPAddr, "err", err)
	} else {
		go s.httpSrv.Serve(ln80)
	}
	s.log.Info("edge listening", "https", s.cfg.HTTPSAddr, "http", s.cfg.HTTPAddr, "tls", s.cfg.TLSMode)
	return nil
}

// Shutdown stops the listeners gracefully.
func (s *Server) Shutdown(ctx context.Context) {
	if s.httpsSrv != nil {
		s.httpsSrv.Shutdown(ctx)
	}
	if s.httpSrv != nil {
		s.httpSrv.Shutdown(ctx)
	}
}
