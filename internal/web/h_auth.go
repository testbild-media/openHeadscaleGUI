package web

import (
	"net/http"
	"strings"
	"time"

	"github.com/testbild-media/openHeadscaleGUI/internal/app"
	"github.com/testbild-media/openHeadscaleGUI/internal/secure"
)

const loginFailMsg = "Anmeldung fehlgeschlagen. Bitte Benutzername und Passwort prüfen."

func safeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") || strings.ContainsAny(next, "\r\n") {
		return "/"
	}
	return next
}

func (s *Server) loginForm(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if rc.User != nil {
		s.redirect(w, r, "/")
		return
	}
	if n, err := s.app.DB.CountUsers(r.Context()); err == nil && n == 0 {
		s.redirect(w, r, "/setup")
		return
	}
	s.render(w, r, rc, http.StatusOK, "login", page{Bare: true, Title: "Anmelden", D: map[string]any{"Next": safeNext(r.URL.Query().Get("next"))}})
}

func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	ctx := r.Context()
	username := strings.TrimSpace(r.PostFormValue("username"))
	password := r.PostFormValue("password")
	next := safeNext(r.PostFormValue("next"))
	fail := func() {
		s.log.Warn("login failed", "user", username, "ip", rc.IP)
		// constant small delay to slow down guessing
		time.Sleep(400 * time.Millisecond)
		s.render(w, r, rc, http.StatusUnauthorized, "login", page{Bare: true, Title: "Anmelden", Flash: &flash{Kind: "err", Msg: loginFailMsg},
			D: map[string]any{"Next": next, "Username": username}})
	}
	if s.loginFails.Blocked(rc.IP) {
		fail()
		return
	}
	if len(username) > 64 || len(password) > 256 || username == "" || password == "" {
		s.loginFails.Fail(rc.IP)
		fail()
		return
	}
	u, err := s.app.DB.GetUserByName(ctx, username)
	hash := ""
	if err == nil {
		hash = u.PasswordHash
	}
	ok, verr := secure.VerifyPassword(ctx, hash, password)
	if err != nil || verr != nil || !ok || u.Disabled || u.Locked(time.Now()) {
		s.loginFails.Fail(rc.IP)
		if u != nil && err == nil {
			_ = s.app.DB.RecordLoginFailure(ctx, u.ID)
			s.app.Audit(ctx, app.Actor{IP: rc.IP}, 0, "login.failed", u.Username)
		}
		fail()
		return
	}
	if rc.Sess != nil {
		s.clearSession(w, r, rc.Sess)
	}
	if u.TOTPEnabled {
		if err := s.createSession(w, r, u, true); err != nil {
			s.fail(w, r, "/login", err)
			return
		}
		s.setCookie(w, "ohg_next", next, 300)
		s.redirect(w, r, "/login/2fa")
		return
	}
	if err := s.createSession(w, r, u, false); err != nil {
		s.fail(w, r, "/login", err)
		return
	}
	s.loginFails.Reset(rc.IP)
	_ = s.app.DB.RecordLoginSuccess(ctx, u.ID)
	s.app.Audit(ctx, app.Actor{User: u, IP: rc.IP}, 0, "login", "")
	s.redirect(w, r, next)
}

func (s *Server) mfaForm(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	s.render(w, r, rc, http.StatusOK, "login2fa", page{Bare: true, Title: "Zwei-Faktor-Anmeldung"})
}

// mfaAttempts counts failed second-factor attempts per pending session.
func (s *Server) mfaSubmit(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	ctx := r.Context()
	key := "mfa|" + rc.Sess.IDHash
	if s.loginFails.Blocked(key) || s.loginFails.Blocked(rc.IP) {
		s.clearSession(w, r, rc.Sess)
		s.setFlash(w, "err", "Zu viele Fehlversuche – bitte erneut anmelden.")
		s.redirect(w, r, "/login")
		return
	}
	code := r.PostFormValue("code")
	if !s.app.Verify2FA(ctx, rc.User, code) {
		s.loginFails.Fail(key)
		s.loginFails.Fail(rc.IP)
		_ = s.app.DB.RecordLoginFailure(ctx, rc.User.ID)
		s.app.Audit(ctx, app.Actor{IP: rc.IP}, 0, "login.2fa_failed", rc.User.Username)
		time.Sleep(400 * time.Millisecond)
		s.render(w, r, rc, http.StatusUnauthorized, "login2fa", page{Bare: true, Title: "Zwei-Faktor-Anmeldung", Flash: &flash{Kind: "err", Msg: "Der Code ist ungültig."}})
		return
	}
	s.clearSession(w, r, rc.Sess)
	if err := s.createSession(w, r, rc.User, false); err != nil {
		s.fail(w, r, "/login", err)
		return
	}
	s.loginFails.Reset(rc.IP)
	_ = s.app.DB.RecordLoginSuccess(ctx, rc.User.ID)
	s.app.Audit(ctx, app.Actor{User: rc.User, IP: rc.IP}, 0, "login", "2FA")
	next := "/"
	if c, err := r.Cookie(s.cookieName("ohg_next")); err == nil {
		next = safeNext(c.Value)
		s.setCookie(w, "ohg_next", "", -1)
	}
	s.redirect(w, r, next)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	s.clearSession(w, r, rc.Sess)
	if rc.User != nil && !rc.Sess.MFAPending {
		s.app.Audit(r.Context(), rc.actor(), 0, "logout", "")
	}
	s.setFlash(w, "ok", "Du wurdest abgemeldet.")
	s.redirect(w, r, "/login")
}

func (s *Server) setupForm(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if n, err := s.app.DB.CountUsers(r.Context()); err != nil || n > 0 {
		s.redirect(w, r, "/login")
		return
	}
	s.render(w, r, rc, http.StatusOK, "setup", page{Bare: true, Title: "Ersteinrichtung"})
}

func (s *Server) setupSubmit(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	ctx := r.Context()
	if n, err := s.app.DB.CountUsers(ctx); err != nil || n > 0 {
		s.redirect(w, r, "/login")
		return
	}
	show := func(msg string) {
		s.render(w, r, rc, http.StatusBadRequest, "setup", page{Bare: true, Title: "Ersteinrichtung", Flash: &flash{Kind: "err", Msg: msg},
			D: map[string]any{"Username": r.PostFormValue("username"), "Email": r.PostFormValue("email")}})
	}
	if s.loginFails.Blocked("setup|" + rc.IP) {
		show("Zu viele Fehlversuche – bitte später erneut versuchen.")
		return
	}
	if !s.app.CheckSetupToken(ctx, r.PostFormValue("token")) {
		s.loginFails.Fail("setup|" + rc.IP)
		time.Sleep(500 * time.Millisecond)
		show("Der Einrichtungs-Code ist ungültig. Er steht im Server-Log bzw. wird von „ohg setup-token“ ausgegeben.")
		return
	}
	if r.PostFormValue("password") != r.PostFormValue("password2") {
		show("Die Passwörter stimmen nicht überein.")
		return
	}
	u, err := s.app.CreateUser(ctx, app.Actor{IP: rc.IP}, app.UserRequest{
		Username: r.PostFormValue("username"), Email: r.PostFormValue("email"), Password: r.PostFormValue("password"),
	})
	if err != nil {
		show(userMessage(err))
		return
	}
	s.app.ClearSetupToken(ctx)
	s.app.Audit(ctx, app.Actor{User: u, IP: rc.IP}, 0, "setup", "Superadmin angelegt")
	if err := s.createSession(w, r, u, false); err != nil {
		s.fail(w, r, "/login", err)
		return
	}
	s.done(w, r, "/profile/2fa", "Willkommen! Bitte richte jetzt die Zwei-Faktor-Anmeldung ein.")
}
