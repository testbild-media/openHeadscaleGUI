package web

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/testbild-media/openHeadscaleGUI/internal/app"
	"github.com/testbild-media/openHeadscaleGUI/internal/gateway"
	"github.com/testbild-media/openHeadscaleGUI/internal/headscale"
	"github.com/testbild-media/openHeadscaleGUI/internal/store"
)

func nodeURL(inst *store.Instance, id uint64) string {
	return instURL(inst, "/nodes/"+strconv.FormatUint(id, 10))
}

func (s *Server) nodeDetail(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	id := pathUint(r, "nid")
	n, err := s.app.FindNode(r.Context(), rc.Inst, id)
	if err != nil {
		if app.IsUserError(err) {
			s.notFound(w, r, rc)
			return
		}
		s.fail(w, r, instURL(rc.Inst, ""), err)
		return
	}
	isGW := s.app.GatewayNodeID(rc.Inst.ID) == id
	type routeRow struct {
		Route    string
		Approved bool
		Serving  bool
	}
	var routes []routeRow
	exitAvail, exitApproved := false, false
	for _, rt := range n.AvailableRoutes {
		approved := contains(n.ApprovedRoutes, rt)
		if rt == "0.0.0.0/0" || rt == "::/0" {
			exitAvail = true
			exitApproved = exitApproved || approved
			continue
		}
		routes = append(routes, routeRow{Route: rt, Approved: approved, Serving: contains(n.SubnetRoutes, rt)})
	}
	// approved but no longer advertised
	for _, rt := range n.ApprovedRoutes {
		if !contains(n.AvailableRoutes, rt) && rt != "0.0.0.0/0" && rt != "::/0" {
			routes = append(routes, routeRow{Route: rt, Approved: true})
		}
	}
	fwds, _ := s.app.DB.ListForwards(r.Context(), rc.Inst.ID)
	var nodeFwds []*store.Forward
	for _, f := range fwds {
		if f.NodeID == int64(id) || (f.NodeID == 0 && (f.TargetHost == n.IPv4() || f.TargetHost == n.IPv6())) {
			nodeFwds = append(nodeFwds, f)
		}
	}
	d := map[string]any{
		"N": n, "IsGateway": isGW, "Routes": routes, "ExitAvail": exitAvail, "ExitApproved": exitApproved,
		"Mon": s.app.Mon.Node(rc.Inst.ID, id), "Forwards": nodeFwds, "Reserved": app.ReservedIPv4(rc.Inst).String(),
		"Expired": n.Expired(time.Now()), "Tags": strings.Join(n.Tags, ", "),
	}
	s.render(w, r, rc, http.StatusOK, "node", page{Title: n.DisplayName(), Nav: "dashboard", Tab: "nodes", D: d})
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func (s *Server) nodeAction(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	id := pathUint(r, "nid")
	back := nodeURL(rc.Inst, id)
	a, act := s.app, rc.actor()
	var err error
	msg := "Gespeichert."
	switch r.PathValue("action") {
	case "rename":
		err = a.RenameNode(ctx, act, rc.Inst, id, r.PostFormValue("name"))
		msg = "Gerät umbenannt."
	case "ip":
		err = a.SetNodeIP(ctx, act, rc.Inst, id, r.PostFormValue("ipv4"))
		msg = "Feste IP gesetzt. Die Instanz wurde kurz neu gestartet, das Gerät übernimmt die Adresse automatisch."
	case "route":
		approve := r.PostFormValue("approve") == "1"
		err = a.SetRouteApproval(ctx, act, rc.Inst, id, r.PostFormValue("route"), approve)
		msg = map[bool]string{true: "Route freigegeben.", false: "Freigabe entzogen."}[approve]
	case "routes-all":
		err = a.ApproveAllRoutes(ctx, act, rc.Inst, id)
		msg = "Alle beworbenen Routen freigegeben."
	case "tags":
		err = a.SetNodeTags(ctx, act, rc.Inst, id, r.PostFormValue("tags"))
		msg = "Tags gespeichert."
	case "expire":
		err = a.ExpireNode(ctx, act, rc.Inst, id)
		msg = "Gerät abgemeldet – es muss sich neu anmelden."
	case "expiry":
		err = a.SetNodeKeyExpiry(ctx, act, rc.Inst, id, formBool(r, "never"), formInt(r, "days"))
		msg = "Ablauf gespeichert."
	case "delete":
		err = a.DeleteNode(ctx, act, rc.Inst, id)
		if err == nil {
			s.done(w, r, instURL(rc.Inst, ""), "Gerät entfernt.")
			return
		}
	case "ping":
		n, ferr := a.FindNode(ctx, rc.Inst, id)
		if ferr != nil {
			err = ferr
			break
		}
		v := a.Mon.PingNow(ctx, rc.Inst.ID, *n)
		if v.PingOK {
			msg = "Ping: " + strconv.FormatFloat(v.PingMs, 'f', 1, 64) + " ms (" + v.PingPath + ")"
		} else {
			err = app.Errf("Ping fehlgeschlagen: %s", v.PingErr)
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

// ---- pending registrations ----

func (s *Server) pendingList(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	ctx := r.Context()
	open, _ := s.app.DB.ListPending(ctx, rc.Inst.ID, true, 100)
	all, _ := s.app.DB.ListPending(ctx, rc.Inst.ID, false, 50)
	var history []*store.PendingRegistration
	for _, p := range all {
		if p.Status != store.PendingOpen {
			history = append(history, p)
		}
	}
	users, err := s.app.HSUsers(ctx, rc.actor(), rc.Inst)
	d := map[string]any{"Open": open, "History": history, "Users": filterUsers(users), "Reserved": app.ReservedIPv4(rc.Inst).String(),
		"URL": s.app.Cfg.PublicURL(rc.Inst.Domain)}
	if err != nil {
		d["UsersErr"] = userMessage(err)
	}
	s.render(w, r, rc, http.StatusOK, "pending", page{Title: "Freigaben – " + rc.Inst.Name, Nav: "dashboard", Tab: "pending", D: d})
}

func filterUsers(users []headscale.User) []headscale.User {
	out := make([]headscale.User, 0, len(users))
	for _, u := range users {
		if u.Name != gateway.SystemUser {
			out = append(out, u)
		}
	}
	return out
}

func approveReq(r *http.Request) app.ApproveRequest {
	return app.ApproveRequest{HSUser: r.PostFormValue("hs_user"), Name: r.PostFormValue("name"), IPv4: r.PostFormValue("ipv4")}
}

func (s *Server) pendingAction(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	back := instURL(rc.Inst, "/pending")
	p, err := s.app.DB.GetPending(ctx, pathInt(r, "pid"))
	if err != nil || p.InstanceID != rc.Inst.ID {
		s.notFound(w, r, rc)
		return
	}
	switch r.PathValue("action") {
	case "approve":
		n, err := s.app.ApprovePending(ctx, rc.actor(), rc.Inst, p, approveReq(r))
		if err != nil {
			s.fail(w, r, back, err)
			return
		}
		if n != nil {
			s.done(w, r, nodeURL(rc.Inst, uint64(n.ID)), "Gerät freigegeben.")
			return
		}
		s.done(w, r, back, "Gerät freigegeben.")
	case "reject":
		if err := s.app.RejectPending(ctx, rc.actor(), rc.Inst, p); err != nil {
			s.fail(w, r, back, err)
			return
		}
		s.done(w, r, back, "Anfrage abgelehnt.")
	default:
		s.notFound(w, r, rc)
	}
}

func (s *Server) pendingManual(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	back := instURL(rc.Inst, "/pending")
	n, err := s.app.ManualRegister(ctx, rc.actor(), rc.Inst, r.PostFormValue("auth"), approveReq(r))
	if err != nil {
		s.fail(w, r, back, err)
		return
	}
	if n != nil {
		s.done(w, r, nodeURL(rc.Inst, uint64(n.ID)), "Gerät registriert.")
		return
	}
	s.done(w, r, back, "Gerät registriert.")
}

// ---- clients: profiles & keys ----

func (s *Server) clientsPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	s.renderClients(w, r, rc, http.StatusOK, nil, nil)
}

func (s *Server) renderClients(w http.ResponseWriter, r *http.Request, rc *reqCtx, status int, created map[string]any, f *flash) {
	ctx := r.Context()
	d := map[string]any{"URL": s.app.Cfg.PublicURL(rc.Inst.Domain), "Reserved": app.ReservedIPv4(rc.Inst).String(), "Created": created}
	profiles, _ := s.app.DB.ListProfiles(ctx, rc.Inst.ID)
	d["Profiles"] = profiles
	users, err := s.app.HSUsers(ctx, rc.actor(), rc.Inst)
	if err != nil {
		d["Err"] = userMessage(err)
	}
	d["Users"] = filterUsers(users)
	keys, err := s.app.PreAuthKeys(ctx, rc.actor(), rc.Inst)
	if err == nil {
		d["Keys"] = keys
	}
	// keys whose connect command can be shown again
	stored, _ := s.app.DB.AuthKeyIDs(ctx, rc.Inst.ID)
	storedKeys := map[headscale.U64]bool{}
	for _, k := range keys {
		_, storedKeys[k.ID] = stored[int64(k.ID)]
	}
	profileKey := map[int64]bool{}
	for _, p := range profiles {
		_, ok := stored[p.PreAuthKeyID]
		profileKey[p.ID] = p.PreAuthKeyID != 0 && ok
	}
	d["Stored"], d["ProfileKey"] = storedKeys, profileKey
	nodes := map[int64]string{}
	for _, n := range s.app.CachedNodes(rc.Inst.ID) {
		nodes[int64(n.ID)] = n.DisplayName() + " (" + n.IPv4() + ")"
	}
	d["NodeNames"] = nodes
	d["Now"] = time.Now()
	s.render(w, r, rc, status, "clients", page{Title: "Clients – " + rc.Inst.Name, Nav: "dashboard", Tab: "clients", Flash: f, D: d})
}

func (s *Server) profileCreate(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	req := app.ProfileRequest{
		Name: r.PostFormValue("name"), HSUser: r.PostFormValue("hs_user"), IPv4: r.PostFormValue("ipv4"),
		AutoExit: formBool(r, "auto_exit"), AutoRoutes: r.PostFormValue("auto_routes"), Hours: formInt(r, "hours"),
		Tags: r.PostFormValue("tags"),
	}
	p, key, err := s.app.CreateProfile(r.Context(), rc.actor(), rc.Inst, req)
	if err != nil {
		if !app.IsUserError(err) {
			s.log.Error("create profile failed", "err", err)
		}
		s.renderClients(w, r, rc, http.StatusBadRequest, nil, &flash{Kind: "err", Msg: userMessage(err)})
		return
	}
	s.renderClients(w, r, rc, http.StatusOK, profileCreated(p, key), &flash{Kind: "ok", Msg: "Client-Profil angelegt."})
}

// profileCreated is the data of the connect box for a client profile.
func profileCreated(p *store.ClientProfile, key *headscale.PreAuthKey) map[string]any {
	return map[string]any{"Key": key.Key, "KeyID": key.ID, "Profile": p, "Expires": key.Expiration,
		"Exit": p.AutoExit, "Routes": strings.Join(p.AutoRouteList(), ",")}
}

// keyCreated is the data of the connect box for a plain pre-auth key.
func keyCreated(key *headscale.PreAuthKey) map[string]any {
	return map[string]any{"Key": key.Key, "KeyID": key.ID, "Expires": key.Expiration, "Reusable": key.Reusable, "Ephemeral": key.Ephemeral}
}

func (s *Server) profileAction(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	ctx := r.Context()
	back := instURL(rc.Inst, "/clients")
	p, err := s.app.DB.GetProfile(ctx, pathInt(r, "pid"))
	if err != nil || p.InstanceID != rc.Inst.ID {
		s.notFound(w, r, rc)
		return
	}
	switch r.PathValue("action") {
	case "update":
		err = s.app.UpdateProfile(ctx, rc.actor(), rc.Inst, p, app.ProfileRequest{
			Name: r.PostFormValue("name"), IPv4: r.PostFormValue("ipv4"), AutoExit: formBool(r, "auto_exit"),
			AutoRoutes: r.PostFormValue("auto_routes"),
		})
		if err == nil {
			s.done(w, r, back, "Profil gespeichert.")
			return
		}
	case "delete":
		err = s.app.DeleteProfile(ctx, rc.actor(), rc.Inst, p)
		if err == nil {
			s.done(w, r, back, "Profil gelöscht.")
			return
		}
	case "showkey":
		var key *headscale.PreAuthKey
		if key, err = s.app.RevealPreAuthKey(ctx, rc.actor(), rc.Inst, uint64(p.PreAuthKeyID)); err == nil {
			s.renderClients(w, r, rc, http.StatusOK, profileCreated(p, key), nil)
			return
		}
	case "newkey":
		var key *headscale.PreAuthKey
		if key, err = s.app.RenewProfileKey(ctx, rc.actor(), rc.Inst, p, formInt(r, "hours")); err == nil {
			s.renderClients(w, r, rc, http.StatusOK, profileCreated(p, key),
				&flash{Kind: "ok", Msg: "Neuer Schlüssel für „" + p.Name + "“ erstellt."})
			return
		}
	default:
		s.notFound(w, r, rc)
		return
	}
	s.fail(w, r, back, err)
}

func (s *Server) keyCreate(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	req := app.KeyRequest{
		HSUser: r.PostFormValue("hs_user"), Reusable: formBool(r, "reusable"), Ephemeral: formBool(r, "ephemeral"),
		Hours: formInt(r, "hours"), Tags: r.PostFormValue("tags"),
	}
	key, err := s.app.CreatePreAuthKey(r.Context(), rc.actor(), rc.Inst, req)
	if err != nil {
		if !app.IsUserError(err) {
			s.log.Error("create key failed", "err", err)
		}
		s.renderClients(w, r, rc, http.StatusBadRequest, nil, &flash{Kind: "err", Msg: userMessage(err)})
		return
	}
	s.renderClients(w, r, rc, http.StatusOK, keyCreated(key), &flash{Kind: "ok", Msg: "Schlüssel erstellt."})
}

func (s *Server) keyAction(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	ctx := r.Context()
	back := instURL(rc.Inst, "/clients")
	id := pathUint(r, "kid")
	var err error
	switch r.PathValue("action") {
	case "show":
		key, err := s.app.RevealPreAuthKey(ctx, rc.actor(), rc.Inst, id)
		if err != nil {
			s.fail(w, r, back, err)
			return
		}
		s.renderClients(w, r, rc, http.StatusOK, keyCreated(key), nil)
		return
	case "expire":
		err = s.app.ExpirePreAuthKey(ctx, rc.actor(), rc.Inst, id)
	case "delete":
		err = s.app.DeletePreAuthKey(ctx, rc.actor(), rc.Inst, id)
	default:
		s.notFound(w, r, rc)
		return
	}
	if err != nil {
		s.fail(w, r, back, err)
		return
	}
	s.done(w, r, back, "Schlüssel aktualisiert.")
}

// ---- tailnet users ----

func (s *Server) hsUsersPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	users, err := s.app.HSUsers(r.Context(), rc.actor(), rc.Inst)
	counts := map[headscale.U64]int{}
	for _, n := range s.app.CachedNodes(rc.Inst.ID) {
		if n.User != nil {
			counts[n.User.ID]++
		}
	}
	d := map[string]any{"Users": users, "Counts": counts, "System": gateway.SystemUser}
	if err != nil {
		d["Err"] = userMessage(err)
	}
	s.render(w, r, rc, http.StatusOK, "hsusers", page{Title: "Tailnet-Benutzer – " + rc.Inst.Name, Nav: "dashboard", Tab: "users", D: d})
}

func (s *Server) hsUserCreate(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	back := instURL(rc.Inst, "/users")
	if err := s.app.CreateHSUser(r.Context(), rc.actor(), rc.Inst, r.PostFormValue("name"), r.PostFormValue("display")); err != nil {
		s.fail(w, r, back, err)
		return
	}
	s.done(w, r, back, "Tailnet-Benutzer angelegt.")
}

func (s *Server) hsUserAction(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	back := instURL(rc.Inst, "/users")
	id := pathUint(r, "uid")
	var err error
	switch r.PathValue("action") {
	case "rename":
		err = s.app.RenameHSUser(r.Context(), rc.actor(), rc.Inst, id, r.PostFormValue("name"))
	case "delete":
		err = s.app.DeleteHSUser(r.Context(), rc.actor(), rc.Inst, id)
	default:
		s.notFound(w, r, rc)
		return
	}
	if err != nil {
		s.fail(w, r, back, err)
		return
	}
	s.done(w, r, back, "Gespeichert.")
}

// ---- policy ----

func (s *Server) policyPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	pol, err := s.app.GetPolicy(r.Context(), rc.actor(), rc.Inst)
	d := map[string]any{"Policy": pol, "Empty": pol == ""}
	if err != nil {
		d["Err"] = userMessage(err)
	}
	if pol == "" {
		d["Policy"] = app.DefaultPolicy
	}
	s.render(w, r, rc, http.StatusOK, "policy", page{Title: "ACL-Policy – " + rc.Inst.Name, Nav: "dashboard", Tab: "policy", D: d})
}

func (s *Server) policySubmit(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	ctx := r.Context()
	pol := strings.ReplaceAll(r.PostFormValue("policy"), "\r\n", "\n")
	render := func(f *flash) {
		s.render(w, r, rc, http.StatusOK, "policy", page{Title: "ACL-Policy – " + rc.Inst.Name, Nav: "dashboard", Tab: "policy", Flash: f,
			D: map[string]any{"Policy": pol}})
	}
	switch r.PostFormValue("action") {
	case "check":
		if err := s.app.CheckPolicy(ctx, rc.actor(), rc.Inst, pol); err != nil {
			render(&flash{Kind: "err", Msg: "Policy ungültig: " + userMessage(err)})
			return
		}
		render(&flash{Kind: "ok", Msg: "Die Policy ist gültig (noch nicht gespeichert)."})
	case "save":
		if err := s.app.SetPolicy(ctx, rc.actor(), rc.Inst, pol); err != nil {
			render(&flash{Kind: "err", Msg: "Speichern fehlgeschlagen: " + userMessage(err)})
			return
		}
		s.done(w, r, instURL(rc.Inst, "/policy"), "Policy gespeichert und aktiv.")
	default:
		s.notFound(w, r, rc)
	}
}
