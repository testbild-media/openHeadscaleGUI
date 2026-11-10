package web

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/testbild-media/openHeadscaleGUI/internal/app"
	"github.com/testbild-media/openHeadscaleGUI/internal/derp"
	"github.com/testbild-media/openHeadscaleGUI/internal/forward"
	"github.com/testbild-media/openHeadscaleGUI/internal/headscale"
	"github.com/testbild-media/openHeadscaleGUI/internal/store"
)

// ---- forwards ----

func (s *Server) forwardsPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	s.renderForwards(w, r, rc, http.StatusOK, app.ForwardRequest{Kind: store.ForwardHTTP, Enabled: true, PreserveHost: true, NodeID: pathIntQuery(r, "node")}, nil)
}

func pathIntQuery(r *http.Request, name string) int64 {
	n, _ := strconv.ParseInt(r.URL.Query().Get(name), 10, 64)
	return n
}

type fwdRow struct {
	F         *store.Forward
	Target    string
	TargetErr string
	C         forward.Snapshot
	ListenErr string
	URL       string
}

func (s *Server) forwardRows(r *http.Request, rc *reqCtx) []fwdRow {
	fwds, _ := s.app.DB.ListForwards(r.Context(), rc.Inst.ID)
	snap := s.app.FwdReg.Snapshot()
	names := map[int64]string{}
	for _, n := range s.app.CachedNodes(rc.Inst.ID) {
		names[int64(n.ID)] = n.DisplayName()
	}
	var rows []fwdRow
	for _, f := range fwds {
		row := fwdRow{F: f, C: snap[f.ID]}
		t, err := s.app.ForwardTarget(f)
		if err != nil {
			row.TargetErr = "Ziel-Gerät fehlt"
		}
		row.Target = t
		if f.NodeID != 0 {
			row.Target = names[f.NodeID] + " (" + t + ")"
		}
		if f.Kind == store.ForwardHTTP {
			row.URL = s.app.Cfg.PublicURL(f.Domain)
		} else {
			row.ListenErr = s.app.Fwd.ListenError(f.Kind, f.PublicPort)
		}
		rows = append(rows, row)
	}
	return rows
}

func (s *Server) renderForwards(w http.ResponseWriter, r *http.Request, rc *reqCtx, status int, req app.ForwardRequest, f *flash) {
	set := s.app.Settings(r.Context())
	d := map[string]any{
		"Rows": s.forwardRows(r, rc), "Nodes": s.app.CachedNodes(rc.Inst.ID), "R": req,
		"PortMin": set.PortMin, "PortMax": set.PortMax, "Suffixes": set.AllowedSuffixes, "GatewayID": s.app.GatewayNodeID(rc.Inst.ID),
	}
	s.render(w, r, rc, status, "forwards", page{Title: "Port-Forwarding – " + rc.Inst.Name, Nav: "dashboard", Tab: "forwards", Flash: f, D: d})
}

func forwardReq(r *http.Request) app.ForwardRequest {
	node, _ := strconv.ParseInt(r.PostFormValue("node_id"), 10, 64)
	return app.ForwardRequest{
		Kind: r.PostFormValue("kind"), Domain: r.PostFormValue("domain"), PublicPort: formInt(r, "public_port"),
		NodeID: node, TargetHost: r.PostFormValue("target_host"), TargetPort: formInt(r, "target_port"),
		UpstreamTLS: formBool(r, "upstream_tls"), UpstreamInsecure: formBool(r, "upstream_insecure"),
		PreserveHost: formBool(r, "preserve_host"), AllowCIDRs: r.PostFormValue("allow_cidrs"),
		BasicAuthUser: r.PostFormValue("basic_user"), BasicAuthPass: r.PostFormValue("basic_pass"),
		Enabled: formBool(r, "enabled"), Description: r.PostFormValue("description"),
	}
}

func (s *Server) forwardCreate(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	req := forwardReq(r)
	if _, err := s.app.CreateForward(r.Context(), rc.actor(), rc.Inst, req); err != nil {
		if !app.IsUserError(err) {
			s.log.Error("create forward failed", "err", err)
		}
		req.BasicAuthPass = ""
		s.renderForwards(w, r, rc, http.StatusBadRequest, req, &flash{Kind: "err", Msg: userMessage(err)})
		return
	}
	s.done(w, r, instURL(rc.Inst, "/forwards"), "Port-Forward angelegt.")
}

func (s *Server) loadForward(w http.ResponseWriter, r *http.Request, rc *reqCtx) *store.Forward {
	f, err := s.app.DB.GetForward(r.Context(), pathInt(r, "fid"))
	if err != nil || f.InstanceID != rc.Inst.ID {
		s.notFound(w, r, rc)
		return nil
	}
	return f
}

func reqFromForward(f *store.Forward) app.ForwardRequest {
	return app.ForwardRequest{
		Kind: f.Kind, Domain: f.Domain, PublicPort: f.PublicPort, NodeID: f.NodeID, TargetHost: f.TargetHost,
		TargetPort: f.TargetPort, UpstreamTLS: f.UpstreamTLS, UpstreamInsecure: f.UpstreamInsecure, PreserveHost: f.PreserveHost,
		AllowCIDRs: f.AllowCIDRs, BasicAuthUser: f.BasicAuthUser, Enabled: f.Enabled, Description: f.Description,
	}
}

func (s *Server) forwardEdit(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	f := s.loadForward(w, r, rc)
	if f == nil {
		return
	}
	s.renderForwardEdit(w, r, rc, http.StatusOK, f, reqFromForward(f), nil)
}

func (s *Server) renderForwardEdit(w http.ResponseWriter, r *http.Request, rc *reqCtx, status int, f *store.Forward, req app.ForwardRequest, fl *flash) {
	set := s.app.Settings(r.Context())
	d := map[string]any{"F": f, "R": req, "Nodes": s.app.CachedNodes(rc.Inst.ID), "PortMin": set.PortMin, "PortMax": set.PortMax,
		"Mon": s.app.Mon.Forward(f.ID), "C": s.app.FwdReg.Get(f.ID).Snapshot(), "HasBasic": f.BasicAuthHash != ""}
	s.render(w, r, rc, status, "forward_edit", page{Title: "Port-Forward bearbeiten", Nav: "dashboard", Tab: "forwards", Flash: fl, D: d})
}

func (s *Server) forwardAction(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	f := s.loadForward(w, r, rc)
	if f == nil {
		return
	}
	ctx := r.Context()
	back := instURL(rc.Inst, "/forwards")
	switch r.PathValue("action") {
	case "update":
		req := forwardReq(r)
		cp := *f
		if err := s.app.UpdateForward(ctx, rc.actor(), rc.Inst, &cp, req); err != nil {
			if !app.IsUserError(err) {
				s.log.Error("update forward failed", "err", err)
			}
			req.BasicAuthPass = ""
			s.renderForwardEdit(w, r, rc, http.StatusBadRequest, f, req, &flash{Kind: "err", Msg: userMessage(err)})
			return
		}
		s.done(w, r, back, "Port-Forward gespeichert.")
	case "toggle":
		if err := s.app.SetForwardEnabled(ctx, rc.actor(), rc.Inst, f, !f.Enabled); err != nil {
			s.fail(w, r, back, err)
			return
		}
		s.done(w, r, back, map[bool]string{true: "Forward aktiviert.", false: "Forward deaktiviert."}[!f.Enabled])
	case "delete":
		if err := s.app.DeleteForward(ctx, rc.actor(), rc.Inst, f); err != nil {
			s.fail(w, r, back, err)
			return
		}
		s.done(w, r, back, "Port-Forward gelöscht.")
	default:
		s.notFound(w, r, rc)
	}
}

// ---- DERP ----

func (s *Server) derpPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	s.renderDERP(w, r, rc, http.StatusOK, s.app.DERPSettings(r.Context()), nil)
}

func (s *Server) renderDERP(w http.ResponseWriter, r *http.Request, rc *reqCtx, status int, ds derp.Settings, f *flash) {
	ctx := r.Context()
	keys, _ := s.app.DB.ListDERPKeys(ctx)
	insts, _ := s.app.DB.ListInstances(ctx, 0)
	stun := ds.STUNPort
	if stun == 0 {
		stun = -1
	}
	preview, _ := headscale.RenderDERPMap(headscale.DERPNode{
		RegionID: ds.RegionID, RegionCode: ds.RegionCode, RegionName: ds.RegionName, Hostname: ds.Domain,
		IPv4: ds.IPv4, IPv6: ds.IPv6, STUNPort: stun, DERPPort: s.app.Cfg.HTTPSPort(),
	})
	d := map[string]any{
		"S": ds, "Stats": s.app.DERP.Stats(), "Mon": s.app.Mon.DERP(), "Keys": keys, "Instances": insts,
		"Clients": s.app.DERPClients(ctx), "Preview": string(preview), "URL": s.app.Cfg.PublicURL(ds.Domain),
	}
	s.render(w, r, rc, status, "derp", page{Title: "DERP-Server", Nav: "derp", Flash: f, D: d})
}

func (s *Server) derpSubmit(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	ds := derp.Settings{
		Enabled: formBool(r, "enabled"), Domain: r.PostFormValue("domain"), RegionID: formInt(r, "region_id"),
		RegionCode: r.PostFormValue("region_code"), RegionName: r.PostFormValue("region_name"),
		STUNPort: formInt(r, "stun_port"), VerifyClients: formBool(r, "verify_clients"), FailOpen: formBool(r, "fail_open"),
		IPv4: strings.TrimSpace(r.PostFormValue("ipv4")), IPv6: strings.TrimSpace(r.PostFormValue("ipv6")),
	}
	if err := s.app.SaveDERPSettings(r.Context(), rc.actor(), ds); err != nil {
		if !app.IsUserError(err) {
			s.log.Error("saving DERP settings failed", "err", err)
		}
		s.renderDERP(w, r, rc, http.StatusBadRequest, ds, &flash{Kind: "err", Msg: userMessage(err)})
		return
	}
	s.done(w, r, "/derp", "DERP-Einstellungen gespeichert und angewendet.")
}

func (s *Server) derpKeySubmit(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	var err error
	if r.PostFormValue("action") == "delete" {
		err = s.app.DeleteDERPKey(r.Context(), rc.actor(), r.PostFormValue("node_key"))
	} else {
		err = s.app.SetDERPKey(r.Context(), rc.actor(), r.PostFormValue("node_key"), r.PostFormValue("mode"), r.PostFormValue("note"))
	}
	if err != nil {
		s.fail(w, r, "/derp", err)
		return
	}
	s.done(w, r, "/derp", "Gespeichert.")
}

// ---- users ----

func (s *Server) usersPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	s.renderUsers(w, r, rc, http.StatusOK, nil, nil)
}

func (s *Server) renderUsers(w http.ResponseWriter, r *http.Request, rc *reqCtx, status int, form map[string]any, f *flash) {
	ctx := r.Context()
	users, _ := s.app.DB.ListUsers(ctx)
	insts, _ := s.app.DB.ListInstances(ctx, 0)
	counts := map[int64]int{}
	for _, i := range insts {
		counts[i.OwnerID]++
	}
	d := map[string]any{"Users": users, "Counts": counts, "Form": form, "DefaultMax": s.app.Settings(ctx).DefaultMaxInst}
	s.render(w, r, rc, status, "users", page{Title: "Benutzer", Nav: "users", Flash: f, D: d})
}

func (s *Server) userCreate(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	req := app.UserRequest{
		Username: r.PostFormValue("username"), Email: r.PostFormValue("email"), Password: r.PostFormValue("password"),
		Role: r.PostFormValue("role"), MaxInstances: formInt(r, "max_instances"), MustChange: formBool(r, "must_change"),
	}
	if _, err := s.app.CreateUser(r.Context(), rc.actor(), req); err != nil {
		s.renderUsers(w, r, rc, http.StatusBadRequest, map[string]any{"Username": req.Username, "Email": req.Email, "Role": req.Role},
			&flash{Kind: "err", Msg: userMessage(err)})
		return
	}
	s.done(w, r, "/users", "Benutzer angelegt.")
}

func (s *Server) loadUser(w http.ResponseWriter, r *http.Request, rc *reqCtx) *store.User {
	u, err := s.app.DB.GetUser(r.Context(), pathInt(r, "uid"))
	if err != nil {
		s.notFound(w, r, rc)
		return nil
	}
	return u
}

func (s *Server) userEdit(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	u := s.loadUser(w, r, rc)
	if u == nil {
		return
	}
	ctx := r.Context()
	insts, _ := s.app.DB.ListInstances(ctx, u.ID)
	sessions, _ := s.app.DB.ListUserSessions(ctx, u.ID)
	s.render(w, r, rc, http.StatusOK, "user_edit", page{Title: "Benutzer " + u.Username, Nav: "users", D: map[string]any{
		"U": u, "Instances": insts, "Sessions": sessions, "Recovery": s.app.DB.CountRecoveryCodes(ctx, u.ID),
	}})
}

func (s *Server) userAction(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	u := s.loadUser(w, r, rc)
	if u == nil {
		return
	}
	ctx := r.Context()
	back := "/users/" + strconv.FormatInt(u.ID, 10)
	var err error
	msg := "Gespeichert."
	switch r.PathValue("action") {
	case "update":
		err = s.app.UpdateUser(ctx, rc.actor(), u, app.UserRequest{
			Email: r.PostFormValue("email"), Role: r.PostFormValue("role"), Disabled: formBool(r, "disabled"),
			MaxInstances: formInt(r, "max_instances"),
		})
	case "password":
		if r.PostFormValue("password") != r.PostFormValue("password2") {
			err = app.Errf("Die Passwörter stimmen nicht überein")
			break
		}
		keep := ""
		if u.ID == rc.User.ID {
			keep = rc.Sess.IDHash
		}
		err = s.app.SetUserPassword(ctx, rc.actor(), u, r.PostFormValue("password"), formBool(r, "must_change"), keep)
		msg = "Passwort gesetzt, alle anderen Sitzungen wurden beendet."
	case "reset2fa":
		err = s.app.ResetUser2FA(ctx, rc.actor(), u)
		msg = "Zwei-Faktor-Anmeldung zurückgesetzt."
	case "unlock":
		err = s.app.UnlockUser(ctx, rc.actor(), u)
		msg = "Sperre aufgehoben."
	case "sessions":
		err = s.app.DB.DeleteUserSessions(ctx, u.ID, rc.Sess.IDHash)
		msg = "Sitzungen beendet."
	case "delete":
		if err = s.app.DeleteUser(ctx, rc.actor(), u); err == nil {
			s.done(w, r, "/users", "Benutzer gelöscht.")
			return
		}
	default:
		s.notFound(w, r, rc)
		return
	}
	if err != nil {
		s.fail(w, r, back, err)
		return
	}
	s.done(w, r, back, msg)
}

// ---- global settings ----

func (s *Server) settingsPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	s.render(w, r, rc, http.StatusOK, "settings", page{Title: "Einstellungen", Nav: "settings", D: map[string]any{
		"S": s.app.Settings(r.Context()), "Cfg": s.app.Cfg, "EnvRequire2FA": s.app.Cfg.Require2FA,
		"HeadscaleVersion": s.app.HeadscaleVersion, "AdminURL": s.app.Cfg.AdminURL(),
	}})
}

func (s *Server) settingsSubmit(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	gs := app.GlobalSettings{
		AllowUserCreate: formBool(r, "allow_user_create"), DefaultMaxInst: formInt(r, "default_max"),
		AllowedSuffixes: app.SplitList(strings.ToLower(r.PostFormValue("suffixes"))), PortMin: formInt(r, "port_min"),
		PortMax: formInt(r, "port_max"), Require2FA: formBool(r, "require_2fa"), AuditDays: formInt(r, "audit_days"),
	}
	if err := s.app.SaveSettings(r.Context(), rc.actor(), gs); err != nil {
		s.fail(w, r, "/settings", err)
		return
	}
	s.done(w, r, "/settings", "Einstellungen gespeichert.")
}

// ---- audit ----

func (s *Server) auditPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	ctx := r.Context()
	pg, _ := strconv.Atoi(r.URL.Query().Get("p"))
	if pg < 0 {
		pg = 0
	}
	const per = 100
	var ids []int64
	var userID int64
	if !rc.User.IsSuperadmin() {
		insts, _ := s.app.DB.ListInstances(ctx, rc.User.ID)
		ids = []int64{}
		for _, i := range insts {
			ids = append(ids, i.ID)
		}
		userID = rc.User.ID
	}
	entries, _ := s.app.DB.ListAudit(ctx, ids, userID, per+1, pg*per)
	more := len(entries) > per
	if more {
		entries = entries[:per]
	}
	insts, _ := s.app.DB.ListInstances(ctx, 0)
	names := map[int64]string{}
	for _, i := range insts {
		names[i.ID] = i.Name
	}
	s.render(w, r, rc, http.StatusOK, "audit", page{Title: "Audit-Log", Nav: "audit", D: map[string]any{
		"Entries": entries, "Names": names, "Page": pg, "More": more,
	}})
}
