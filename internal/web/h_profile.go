package web

import (
	"net/http"

	"github.com/testbild-media/openHeadscaleGUI/internal/app"
)

func (s *Server) profilePage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	ctx := r.Context()
	sessions, _ := s.app.DB.ListUserSessions(ctx, rc.User.ID)
	s.render(w, r, rc, http.StatusOK, "profile", page{Title: "Profil", Nav: "profile", D: map[string]any{
		"Sessions": sessions, "Current": rc.Sess.IDHash, "Recovery": s.app.DB.CountRecoveryCodes(ctx, rc.User.ID),
	}})
}

func (s *Server) profilePasswordForm(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	s.render(w, r, rc, http.StatusOK, "password", page{Title: "Passwort ändern", Nav: "profile"})
}

func (s *Server) profilePassword(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	ctx := r.Context()
	show := func(msg string) {
		s.render(w, r, rc, http.StatusBadRequest, "password", page{Title: "Passwort ändern", Nav: "profile", Flash: &flash{Kind: "err", Msg: msg}})
	}
	key := "pw|" + rc.Sess.IDHash
	if s.loginFails.Blocked(key) {
		show("Zu viele Fehlversuche – bitte später erneut versuchen.")
		return
	}
	ok, err := verifyCurrent(r, rc.User.PasswordHash, r.PostFormValue("current"))
	if err != nil || !ok {
		s.loginFails.Fail(key)
		show("Das aktuelle Passwort ist falsch.")
		return
	}
	if r.PostFormValue("password") != r.PostFormValue("password2") {
		show("Die neuen Passwörter stimmen nicht überein.")
		return
	}
	if r.PostFormValue("password") == r.PostFormValue("current") {
		show("Das neue Passwort muss sich vom alten unterscheiden.")
		return
	}
	if err := s.app.SetUserPassword(ctx, rc.actor(), rc.User, r.PostFormValue("password"), false, rc.Sess.IDHash); err != nil {
		show(userMessage(err))
		return
	}
	s.done(w, r, "/profile", "Passwort geändert. Alle anderen Sitzungen wurden beendet.")
}

func (s *Server) twoFAPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	d := map[string]any{"Enabled": rc.User.TOTPEnabled, "Required": s.app.Settings(r.Context()).Require2FA,
		"Recovery": s.app.DB.CountRecoveryCodes(r.Context(), rc.User.ID)}
	s.render(w, r, rc, http.StatusOK, "twofa", page{Title: "Zwei-Faktor-Anmeldung", Nav: "profile", D: d})
}

func (s *Server) twoFAAction(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	ctx := r.Context()
	switch r.PathValue("action") {
	case "begin":
		if rc.User.TOTPEnabled {
			s.redirect(w, r, "/profile/2fa")
			return
		}
		secret, uri, qr, err := s.app.Begin2FA(ctx, rc.User)
		if err != nil {
			s.fail(w, r, "/profile/2fa", err)
			return
		}
		s.render(w, r, rc, http.StatusOK, "twofa", page{Title: "Zwei-Faktor-Anmeldung", Nav: "profile", D: map[string]any{
			"Setup": true, "Secret": secret, "URI": uri, "QR": qrURL(qr),
		}})
	case "enable":
		u, err := s.app.DB.GetUser(ctx, rc.User.ID)
		if err != nil {
			s.fail(w, r, "/profile/2fa", err)
			return
		}
		codes, err := s.app.Enable2FA(ctx, rc.actor(), u, r.PostFormValue("code"))
		if err != nil {
			s.fail(w, r, "/profile/2fa", err)
			return
		}
		// other sessions must log in again with 2FA
		_ = s.app.DB.DeleteUserSessions(ctx, u.ID, rc.Sess.IDHash)
		s.render(w, r, rc, http.StatusOK, "recovery", page{Title: "Recovery-Codes", Nav: "profile",
			Flash: &flash{Kind: "ok", Msg: "Zwei-Faktor-Anmeldung aktiviert."}, D: map[string]any{"Codes": codes}})
	case "disable":
		if s.app.Settings(ctx).Require2FA {
			s.fail(w, r, "/profile/2fa", app.Errf("Die Zwei-Faktor-Anmeldung ist verpflichtend"))
			return
		}
		if err := s.app.Disable2FA(ctx, rc.actor(), rc.User, r.PostFormValue("code")); err != nil {
			s.fail(w, r, "/profile/2fa", err)
			return
		}
		s.done(w, r, "/profile/2fa", "Zwei-Faktor-Anmeldung deaktiviert.")
	case "recovery":
		if !rc.User.TOTPEnabled || !s.app.Verify2FA(ctx, rc.User, r.PostFormValue("code")) {
			s.fail(w, r, "/profile/2fa", app.Errf("Der Code ist ungültig"))
			return
		}
		codes, err := s.app.NewRecoveryCodes(ctx, rc.User)
		if err != nil {
			s.fail(w, r, "/profile/2fa", err)
			return
		}
		s.app.Audit(ctx, rc.actor(), 0, "user.recovery_codes", rc.User.Username)
		s.render(w, r, rc, http.StatusOK, "recovery", page{Title: "Recovery-Codes", Nav: "profile", D: map[string]any{"Codes": codes}})
	default:
		s.notFound(w, r, rc)
	}
}

func (s *Server) sessionAction(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	ctx := r.Context()
	switch r.PathValue("action") {
	case "revoke":
		id := r.PostFormValue("id")
		sessions, _ := s.app.DB.ListUserSessions(ctx, rc.User.ID)
		for _, ss := range sessions {
			if ss.IDHash == id {
				_ = s.app.DB.DeleteSession(ctx, id)
			}
		}
		if id == rc.Sess.IDHash {
			s.clearSession(w, r, nil)
			s.redirect(w, r, "/login")
			return
		}
	case "revoke-all":
		_ = s.app.DB.DeleteUserSessions(ctx, rc.User.ID, rc.Sess.IDHash)
	default:
		s.notFound(w, r, rc)
		return
	}
	s.done(w, r, "/profile", "Sitzungen aktualisiert.")
}
