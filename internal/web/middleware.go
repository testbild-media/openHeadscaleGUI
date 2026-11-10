package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/testbild-media/openHeadscaleGUI/internal/app"
	"github.com/testbild-media/openHeadscaleGUI/internal/edge"
	"github.com/testbild-media/openHeadscaleGUI/internal/forward"
	"github.com/testbild-media/openHeadscaleGUI/internal/secure"
	"github.com/testbild-media/openHeadscaleGUI/internal/store"
)

const (
	sessionCookie = "ohg_session"
	preCSRFCookie = "ohg_csrf"
	flashCookie   = "ohg_flash"
	maxBodyBytes  = 1 << 20
)

// reqCtx carries the request-scoped state.
type reqCtx struct {
	User  *store.User
	Sess  *store.Session
	Inst  *store.Instance
	IP    string
	CSRF  string
	Token string
}

func (rc *reqCtx) actor() app.Actor { return app.Actor{User: rc.User, IP: rc.IP} }

type handler func(w http.ResponseWriter, r *http.Request, rc *reqCtx)

func (s *Server) cookieName(base string) string {
	if s.app.Cfg.SecureCookies() {
		return "__Host-" + base
	}
	return base
}

func (s *Server) setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName(name),
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   s.app.Cfg.SecureCookies(),
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) adminOrigin() string {
	u, err := url.Parse(s.app.Cfg.AdminURL())
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// chain applies the global middleware to the admin GUI.
func (s *Server) chain(next http.Handler) http.Handler {
	csp := "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; " +
		"connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				s.log.Error("panic in handler", "err", v, "path", r.URL.Path, "stack", string(debug.Stack()))
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		ip := edge.ClientIP(r)
		if len(s.app.Cfg.AdminAllowCIDRs) > 0 && !forward.Allowed(s.app.Cfg.AdminAllowCIDRs, ip) {
			http.NotFound(w, r)
			return
		}
		if !s.reqLimit.Allow(ip.String()) {
			w.Header().Set("Retry-After", "5")
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		// same-origin (not no-referrer): with no-referrer browsers send
		// "Origin: null" on form posts, which defeats the origin check.
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		if !s.app.Cfg.PlainHTTP() {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		if !strings.HasPrefix(r.URL.Path, "/static/") {
			h.Set("Cache-Control", "no-store")
		}
		switch r.Method {
		case http.MethodGet, http.MethodHead:
		case http.MethodPost:
			sfs := r.Header.Get("Sec-Fetch-Site")
			origin := r.Header.Get("Origin")
			switch {
			case origin == "":
			case origin == "null" && sfs == "same-origin":
				// privacy-preserving browsers may send a null origin
			case origin != s.adminOrigin():
				http.Error(w, "cross-origin request rejected", http.StatusForbidden)
				return
			}
			if sfs != "" && sfs != "same-origin" && sfs != "none" {
				http.Error(w, "cross-site request rejected", http.StatusForbidden)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) newReqCtx(r *http.Request) *reqCtx {
	return &reqCtx{IP: edge.ClientIP(r).String()}
}

// loadSession returns the session and user for the request, if valid.
func (s *Server) loadSession(r *http.Request) (*store.Session, *store.User, string) {
	c, err := r.Cookie(s.cookieName(sessionCookie))
	if err != nil || len(c.Value) < 32 || len(c.Value) > 128 {
		return nil, nil, ""
	}
	ctx := r.Context()
	sess, err := s.app.DB.GetSession(ctx, secure.HashToken(c.Value))
	if err != nil {
		return nil, nil, ""
	}
	now := time.Now().Unix()
	if sess.ExpiresAt < now || (!sess.MFAPending && now-sess.LastSeenAt > int64(s.app.Cfg.SessionIdle.Seconds())) {
		_ = s.app.DB.DeleteSession(ctx, sess.IDHash)
		return nil, nil, ""
	}
	u, err := s.app.DB.GetUser(ctx, sess.UserID)
	if err != nil || u.Disabled {
		_ = s.app.DB.DeleteSession(ctx, sess.IDHash)
		return nil, nil, ""
	}
	if now-sess.LastSeenAt > 30 {
		_ = s.app.DB.TouchSession(ctx, sess.IDHash, now)
	}
	return sess, u, c.Value
}

// createSession creates a new session and sets the cookie.
func (s *Server) createSession(w http.ResponseWriter, r *http.Request, u *store.User, mfaPending bool) error {
	token := secure.RandomToken(32)
	now := time.Now()
	exp := now.Add(s.app.Cfg.SessionMax)
	if mfaPending {
		exp = now.Add(5 * time.Minute)
	}
	ua := r.UserAgent()
	if len(ua) > 200 {
		ua = ua[:200]
	}
	sess := &store.Session{
		IDHash: secure.HashToken(token), UserID: u.ID, CSRF: secure.RandomToken(24), MFAPending: mfaPending,
		CreatedAt: now.Unix(), LastSeenAt: now.Unix(), ExpiresAt: exp.Unix(), IP: edge.ClientIP(r).String(), UserAgent: ua,
	}
	if err := s.app.DB.CreateSession(r.Context(), sess); err != nil {
		return err
	}
	s.setCookie(w, sessionCookie, token, int(time.Until(exp).Seconds()))
	return nil
}

func (s *Server) clearSession(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	if sess != nil {
		_ = s.app.DB.DeleteSession(r.Context(), sess.IDHash)
	}
	s.setCookie(w, sessionCookie, "", -1)
}

func (s *Server) checkCSRF(r *http.Request, want string) bool {
	if r.Method != http.MethodPost {
		return true
	}
	got := r.PostFormValue("_csrf")
	return want != "" && got != "" && secure.ConstantTimeEqual(got, want)
}

// preCSRF returns (and sets) the double-submit token for login/setup forms.
func (s *Server) preCSRF(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(s.cookieName(preCSRFCookie)); err == nil && len(c.Value) >= 32 && len(c.Value) <= 64 {
		return c.Value
	}
	t := secure.RandomToken(24)
	s.setCookie(w, preCSRFCookie, t, 3600)
	return t
}

func badCSRF(w http.ResponseWriter) {
	http.Error(w, "Ungültiges oder abgelaufenes Formular. Bitte die Seite neu laden.", http.StatusForbidden)
}

// public handlers do not require a session (login, setup).
func (s *Server) public(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rc := s.newReqCtx(r)
		if sess, u, _ := s.loadSession(r); sess != nil && !sess.MFAPending {
			rc.User, rc.Sess = u, sess
		}
		rc.CSRF = s.preCSRF(w, r)
		if r.Method == http.MethodPost {
			c, err := r.Cookie(s.cookieName(preCSRFCookie))
			if err != nil || !s.checkCSRF(r, c.Value) {
				badCSRF(w)
				return
			}
		}
		h(w, r, rc)
	}
}

// mfa handlers require a session waiting for the second factor.
func (s *Server) mfa(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, u, tok := s.loadSession(r)
		if sess == nil || !sess.MFAPending {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		rc := s.newReqCtx(r)
		rc.User, rc.Sess, rc.CSRF, rc.Token = u, sess, sess.CSRF, tok
		if !s.checkCSRF(r, sess.CSRF) {
			badCSRF(w)
			return
		}
		h(w, r, rc)
	}
}

// anySession accepts pending and full sessions (logout).
func (s *Server) anySession(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, u, tok := s.loadSession(r)
		rc := s.newReqCtx(r)
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		rc.User, rc.Sess, rc.CSRF, rc.Token = u, sess, sess.CSRF, tok
		if !s.checkCSRF(r, sess.CSRF) {
			badCSRF(w)
			return
		}
		h(w, r, rc)
	}
}

type authOpts struct {
	allowMustChange bool
	allowNo2FA      bool
	superadmin      bool
}

func (s *Server) authWith(o authOpts, h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, u, tok := s.loadSession(r)
		if sess == nil || sess.MFAPending {
			if n, err := s.app.DB.CountUsers(r.Context()); err == nil && n == 0 {
				http.Redirect(w, r, "/setup", http.StatusSeeOther)
				return
			}
			next := "/login"
			if r.Method == http.MethodGet && r.URL.Path != "/" {
				next += "?next=" + url.QueryEscape(r.URL.RequestURI())
			}
			http.Redirect(w, r, next, http.StatusSeeOther)
			return
		}
		rc := s.newReqCtx(r)
		rc.User, rc.Sess, rc.CSRF, rc.Token = u, sess, sess.CSRF, tok
		if !s.checkCSRF(r, sess.CSRF) {
			badCSRF(w)
			return
		}
		if u.MustChangePassword && !o.allowMustChange {
			http.Redirect(w, r, "/profile/password", http.StatusSeeOther)
			return
		}
		if !u.TOTPEnabled && !o.allowNo2FA && !o.allowMustChange && s.app.Settings(r.Context()).Require2FA {
			http.Redirect(w, r, "/profile/2fa", http.StatusSeeOther)
			return
		}
		if o.superadmin && !u.IsSuperadmin() {
			s.notFound(w, r, rc)
			return
		}
		h(w, r, rc)
	}
}

func (s *Server) auth(h handler) http.HandlerFunc { return s.authWith(authOpts{}, h) }
func (s *Server) authAllowPw(h handler) http.HandlerFunc {
	return s.authWith(authOpts{allowMustChange: true}, h)
}
func (s *Server) auth2FASetup(h handler) http.HandlerFunc {
	return s.authWith(authOpts{allowNo2FA: true}, h)
}
func (s *Server) admin(h handler) http.HandlerFunc { return s.authWith(authOpts{superadmin: true}, h) }

// inst loads {id} and checks that the user may manage it.
func (s *Server) inst(h handler) http.HandlerFunc {
	return s.auth(func(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			s.notFound(w, r, rc)
			return
		}
		inst, err := s.app.DB.GetInstance(r.Context(), id)
		if err != nil || !app.CanManage(rc.User, inst) {
			s.notFound(w, r, rc)
			return
		}
		rc.Inst = inst
		h(w, r, rc)
	})
}

func pathInt(r *http.Request, name string) int64 {
	n, _ := strconv.ParseInt(r.PathValue(name), 10, 64)
	return n
}

func pathUint(r *http.Request, name string) uint64 {
	n, _ := strconv.ParseUint(r.PathValue(name), 10, 64)
	return n
}

func formInt(r *http.Request, name string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(r.PostFormValue(name)))
	return n
}

func formBool(r *http.Request, name string) bool {
	v := r.PostFormValue(name)
	return v == "1" || v == "on" || v == "true"
}

// userMessage turns an error into something safe to show.
func userMessage(err error) string {
	var ue *app.UserError
	switch {
	case err == nil:
		return ""
	case errors.As(err, &ue):
		return ue.Msg
	case errors.Is(err, app.ErrForbidden):
		return "Keine Berechtigung"
	case errors.Is(err, context.DeadlineExceeded):
		return "Zeitüberschreitung – bitte erneut versuchen"
	}
	return "Interner Fehler – Details im Server-Log"
}
