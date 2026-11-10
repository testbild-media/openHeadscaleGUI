// Package web implements the admin GUI.
package web

import (
	"embed"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/testbild-media/openHeadscaleGUI/internal/app"
	"github.com/testbild-media/openHeadscaleGUI/internal/ratelimit"
)

//go:embed templates/*.html static/*
var assets embed.FS

// Server is the admin GUI.
type Server struct {
	app  *app.App
	log  *slog.Logger
	tpl  *templates
	mux  *http.ServeMux
	root http.Handler

	reqLimit    *ratelimit.Limiter
	loginFails  *ratelimit.Failures
	staticFiles fs.FS
	started     time.Time
}

// New creates the GUI server.
func New(a *app.App) (*Server, error) {
	tpl, err := loadTemplates()
	if err != nil {
		return nil, err
	}
	static, _ := fs.Sub(assets, "static")
	s := &Server{
		app:         a,
		log:         a.Log.With("component", "web"),
		tpl:         tpl,
		mux:         http.NewServeMux(),
		reqLimit:    ratelimit.New(20, 120),
		loginFails:  ratelimit.NewFailures(10, 15*time.Minute, 15*time.Minute),
		staticFiles: static,
		started:     time.Now(),
	}
	s.routes()
	s.root = s.chain(s.mux)
	return s, nil
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.root.ServeHTTP(w, r) }

func (s *Server) routes() {
	m := s.mux
	m.Handle("GET /static/", http.StripPrefix("/static/", s.staticHandler()))
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	m.HandleFunc("GET /robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("User-agent: *\nDisallow: /\n"))
	})

	// authentication
	m.HandleFunc("GET /login", s.public(s.loginForm))
	m.HandleFunc("POST /login", s.public(s.loginSubmit))
	m.HandleFunc("GET /login/2fa", s.mfa(s.mfaForm))
	m.HandleFunc("POST /login/2fa", s.mfa(s.mfaSubmit))
	m.HandleFunc("POST /logout", s.anySession(s.logout))
	m.HandleFunc("GET /setup", s.public(s.setupForm))
	m.HandleFunc("POST /setup", s.public(s.setupSubmit))

	// dashboard & instances
	m.HandleFunc("GET /{$}", s.auth(s.dashboard))
	m.HandleFunc("GET /instances/new", s.auth(s.instanceNew))
	m.HandleFunc("POST /instances", s.auth(s.instanceCreate))
	m.HandleFunc("GET /i/{id}", s.inst(s.instanceOverview))
	m.HandleFunc("GET /i/{id}/nodes/{nid}", s.inst(s.nodeDetail))
	m.HandleFunc("POST /i/{id}/nodes/{nid}/{action}", s.inst(s.nodeAction))
	m.HandleFunc("GET /i/{id}/pending", s.inst(s.pendingList))
	m.HandleFunc("POST /i/{id}/pending/manual", s.inst(s.pendingManual))
	m.HandleFunc("POST /i/{id}/pending/{pid}/{action}", s.inst(s.pendingAction))
	m.HandleFunc("GET /i/{id}/clients", s.inst(s.clientsPage))
	m.HandleFunc("POST /i/{id}/profiles", s.inst(s.profileCreate))
	m.HandleFunc("POST /i/{id}/profiles/{pid}/{action}", s.inst(s.profileAction))
	m.HandleFunc("POST /i/{id}/keys", s.inst(s.keyCreate))
	m.HandleFunc("POST /i/{id}/keys/{kid}/{action}", s.inst(s.keyAction))
	m.HandleFunc("GET /i/{id}/users", s.inst(s.hsUsersPage))
	m.HandleFunc("POST /i/{id}/users", s.inst(s.hsUserCreate))
	m.HandleFunc("POST /i/{id}/users/{uid}/{action}", s.inst(s.hsUserAction))
	m.HandleFunc("GET /i/{id}/forwards", s.inst(s.forwardsPage))
	m.HandleFunc("POST /i/{id}/forwards", s.inst(s.forwardCreate))
	m.HandleFunc("GET /i/{id}/forwards/{fid}", s.inst(s.forwardEdit))
	m.HandleFunc("POST /i/{id}/forwards/{fid}/{action}", s.inst(s.forwardAction))
	m.HandleFunc("GET /i/{id}/policy", s.inst(s.policyPage))
	m.HandleFunc("POST /i/{id}/policy", s.inst(s.policySubmit))
	m.HandleFunc("GET /i/{id}/monitor", s.inst(s.monitorPage))
	m.HandleFunc("GET /i/{id}/settings", s.inst(s.instanceSettings))
	m.HandleFunc("POST /i/{id}/settings", s.inst(s.instanceSettingsSubmit))
	m.HandleFunc("POST /i/{id}/state", s.inst(s.instanceState))
	m.HandleFunc("POST /i/{id}/delete", s.inst(s.instanceDelete))
	m.HandleFunc("GET /i/{id}/logs", s.inst(s.instanceLogs))

	// superadmin
	m.HandleFunc("GET /derp", s.admin(s.derpPage))
	m.HandleFunc("POST /derp", s.admin(s.derpSubmit))
	m.HandleFunc("POST /derp/keys", s.admin(s.derpKeySubmit))
	m.HandleFunc("GET /users", s.admin(s.usersPage))
	m.HandleFunc("POST /users", s.admin(s.userCreate))
	m.HandleFunc("GET /users/{uid}", s.admin(s.userEdit))
	m.HandleFunc("POST /users/{uid}/{action}", s.admin(s.userAction))
	m.HandleFunc("GET /settings", s.admin(s.settingsPage))
	m.HandleFunc("POST /settings", s.admin(s.settingsSubmit))

	// everyone
	m.HandleFunc("GET /audit", s.auth(s.auditPage))
	m.HandleFunc("GET /profile", s.auth(s.profilePage))
	m.HandleFunc("POST /profile/password", s.authAllowPw(s.profilePassword))
	m.HandleFunc("GET /profile/password", s.authAllowPw(s.profilePasswordForm))
	m.HandleFunc("GET /profile/2fa", s.auth2FASetup(s.twoFAPage))
	m.HandleFunc("POST /profile/2fa/{action}", s.auth2FASetup(s.twoFAAction))
	m.HandleFunc("POST /profile/sessions/{action}", s.auth(s.sessionAction))
}

func (s *Server) staticHandler() http.Handler {
	fsrv := http.FileServer(http.FS(s.staticFiles))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "" || r.URL.Path[len(r.URL.Path)-1] == '/' {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=3600")
		fsrv.ServeHTTP(w, r)
	})
}
