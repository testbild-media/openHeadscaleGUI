package web

import (
	"net/http"

	"github.com/testbild-media/openHeadscaleGUI/internal/app"
	"github.com/testbild-media/openHeadscaleGUI/internal/forward"
	"github.com/testbild-media/openHeadscaleGUI/internal/store"
)

type redirectRow struct {
	R     *store.Redirect
	URL   string // public URL of the redirect domain
	Owner string
	C     forward.Snapshot
}

func (s *Server) redirectRows(r *http.Request, rc *reqCtx) []redirectRow {
	reds, _ := s.app.Redirects(r.Context(), rc.actor())
	users := map[int64]string{}
	if rc.User.IsSuperadmin() {
		if list, err := s.app.DB.ListUsers(r.Context()); err == nil {
			for _, u := range list {
				users[u.ID] = u.Username
			}
		}
	}
	snap := s.app.RedirectReg.Snapshot()
	rows := make([]redirectRow, 0, len(reds))
	for _, d := range reds {
		rows = append(rows, redirectRow{R: d, URL: s.app.Cfg.PublicURL(d.Domain), Owner: users[d.OwnerID], C: snap[d.ID]})
	}
	return rows
}

func (s *Server) redirectsPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	s.renderRedirects(w, r, rc, http.StatusOK, app.RedirectRequest{Code: http.StatusFound, KeepPath: true, Enabled: true}, nil)
}

func (s *Server) renderRedirects(w http.ResponseWriter, r *http.Request, rc *reqCtx, status int, req app.RedirectRequest, f *flash) {
	set := s.app.Settings(r.Context())
	d := map[string]any{"Rows": s.redirectRows(r, rc), "R": req, "Suffixes": set.AllowedSuffixes, "Super": rc.User.IsSuperadmin()}
	s.render(w, r, rc, status, "redirects", page{Title: "Weiterleitungen", Nav: "redirects", Flash: f, D: d})
}

func redirectReq(r *http.Request) app.RedirectRequest {
	return app.RedirectRequest{
		Domain: r.PostFormValue("domain"), URL: r.PostFormValue("url"), Code: formInt(r, "code"),
		KeepPath: formBool(r, "keep_path"), AllowCIDRs: r.PostFormValue("allow_cidrs"), Enabled: formBool(r, "enabled"),
		Description: r.PostFormValue("description"),
	}
}

func (s *Server) redirectCreate(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	req := redirectReq(r)
	if _, err := s.app.CreateRedirect(r.Context(), rc.actor(), req); err != nil {
		if !app.IsUserError(err) && err != app.ErrForbidden {
			s.log.Error("create redirect failed", "err", err)
		}
		s.renderRedirects(w, r, rc, http.StatusBadRequest, req, &flash{Kind: "err", Msg: userMessage(err)})
		return
	}
	s.done(w, r, "/redirects", "Weiterleitung angelegt.")
}

func (s *Server) loadRedirect(w http.ResponseWriter, r *http.Request, rc *reqCtx) *store.Redirect {
	d, err := s.app.DB.GetRedirect(r.Context(), pathInt(r, "rid"))
	if err != nil || !app.CanManageRedirect(rc.User, d) {
		s.notFound(w, r, rc)
		return nil
	}
	return d
}

func (s *Server) redirectEdit(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	d := s.loadRedirect(w, r, rc)
	if d == nil {
		return
	}
	s.renderRedirectEdit(w, r, rc, http.StatusOK, d, app.RedirectRequestFrom(d), nil)
}

func (s *Server) renderRedirectEdit(w http.ResponseWriter, r *http.Request, rc *reqCtx, status int, d *store.Redirect, req app.RedirectRequest, f *flash) {
	set := s.app.Settings(r.Context())
	data := map[string]any{"Red": d, "R": req, "Suffixes": set.AllowedSuffixes, "C": s.app.RedirectReg.Get(d.ID).Snapshot(),
		"URL": s.app.Cfg.PublicURL(d.Domain)}
	s.render(w, r, rc, status, "redirect_edit", page{Title: "Weiterleitung bearbeiten", Nav: "redirects", Flash: f, D: data})
}

func (s *Server) redirectAction(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	d := s.loadRedirect(w, r, rc)
	if d == nil {
		return
	}
	ctx := r.Context()
	switch r.PathValue("action") {
	case "update":
		req := redirectReq(r)
		cp := *d
		if err := s.app.UpdateRedirect(ctx, rc.actor(), &cp, req); err != nil {
			s.renderRedirectEdit(w, r, rc, http.StatusBadRequest, d, req, &flash{Kind: "err", Msg: userMessage(err)})
			return
		}
		s.done(w, r, "/redirects", "Weiterleitung gespeichert.")
	case "toggle":
		if err := s.app.SetRedirectEnabled(ctx, rc.actor(), d, !d.Enabled); err != nil {
			s.fail(w, r, "/redirects", err)
			return
		}
		s.done(w, r, "/redirects", map[bool]string{true: "Weiterleitung aktiviert.", false: "Weiterleitung deaktiviert."}[d.Enabled])
	case "delete":
		if err := s.app.DeleteRedirect(ctx, rc.actor(), d); err != nil {
			s.fail(w, r, "/redirects", err)
			return
		}
		s.done(w, r, "/redirects", "Weiterleitung gelöscht.")
	default:
		s.notFound(w, r, rc)
	}
}
