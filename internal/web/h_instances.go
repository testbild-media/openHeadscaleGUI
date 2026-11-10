package web

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/testbild-media/openHeadscaleGUI/internal/app"
	"github.com/testbild-media/openHeadscaleGUI/internal/gateway"
	"github.com/testbild-media/openHeadscaleGUI/internal/headscale"
	"github.com/testbild-media/openHeadscaleGUI/internal/monitor"
	"github.com/testbild-media/openHeadscaleGUI/internal/store"
)

func instURL(inst *store.Instance, rest string) string {
	return "/i/" + strconv.FormatInt(inst.ID, 10) + rest
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	ctx := r.Context()
	sums, err := s.app.Summaries(ctx, rc.User)
	if err != nil {
		s.fail(w, r, "/profile", err)
		return
	}
	d := map[string]any{"Instances": sums}
	var totalNodes, online, pending int
	var rx, tx float64
	for _, x := range sums {
		totalNodes += x.NodesTotal
		online += x.NodesOnline
		pending += x.Pending
		rx += x.RxRate
		tx += x.TxRate
	}
	d["TotalNodes"], d["Online"], d["Pending"], d["Rx"], d["Tx"] = totalNodes, online, pending, rx, tx
	if rc.User.IsSuperadmin() {
		ds := s.app.DERPSettings(ctx)
		d["DERP"] = ds
		d["DERPStats"] = s.app.DERP.Stats()
		d["DERPMon"] = s.app.Mon.DERP()
		d["HeadscaleVersion"] = s.app.HeadscaleVersion
	}
	n, _ := s.app.DB.CountInstancesByOwner(ctx, rc.User.ID)
	d["CanCreate"] = rc.User.IsSuperadmin() || (s.app.Settings(ctx).AllowUserCreate && n < rc.User.MaxInstances)
	s.render(w, r, rc, http.StatusOK, "dashboard", page{Title: "Übersicht", Nav: "dashboard", D: d})
}

func (s *Server) instanceNew(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	p := app.DefaultInstanceParams()
	s.renderInstanceForm(w, r, rc, http.StatusOK, p, "")
}

func (s *Server) renderInstanceForm(w http.ResponseWriter, r *http.Request, rc *reqCtx, status int, p app.InstanceParams, errMsg string) {
	ctx := r.Context()
	d := map[string]any{"P": p, "DERP": s.app.DERPSettings(ctx), "Suffixes": s.app.Settings(ctx).AllowedSuffixes}
	if rc.User.IsSuperadmin() {
		d["Users"], _ = s.app.DB.ListUsers(ctx)
	}
	var f *flash
	if errMsg != "" {
		f = &flash{Kind: "err", Msg: errMsg}
	}
	s.render(w, r, rc, status, "instance_new", page{Title: "Neue Instanz", Nav: "dashboard", Flash: f, D: d})
}

func paramsFromForm(r *http.Request, p app.InstanceParams) app.InstanceParams {
	p.Name = r.PostFormValue("name")
	p.Domain = r.PostFormValue("domain")
	if v := r.PostFormValue("prefix_v4"); v != "" {
		p.PrefixV4 = v
	}
	if v := r.PostFormValue("prefix_v6"); v != "" {
		p.PrefixV6 = v
	}
	p.IPAllocation = r.PostFormValue("ip_allocation")
	p.MagicDNS = formBool(r, "magic_dns")
	p.BaseDomain = r.PostFormValue("base_domain")
	p.Nameservers = r.PostFormValue("nameservers")
	p.OverrideLocalDNS = formBool(r, "override_local_dns")
	p.UseCentralDERP = formBool(r, "use_central_derp")
	p.UsePublicDERP = formBool(r, "use_public_derp")
	p.GatewayExitNode = formBool(r, "gateway_exit_node")
	if v := strings.TrimSpace(r.PostFormValue("node_expiry")); v != "" {
		p.NodeExpiry = v
	}
	if v := strings.TrimSpace(r.PostFormValue("ephemeral_timeout")); v != "" {
		p.EphemeralTimeout = v
	}
	if v, err := strconv.ParseInt(r.PostFormValue("owner_id"), 10, 64); err == nil {
		p.OwnerID = v
	}
	return p
}

func (s *Server) instanceCreate(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	p := paramsFromForm(r, app.DefaultInstanceParams())
	p.Slug = r.PostFormValue("slug")
	inst, err := s.app.CreateInstance(r.Context(), rc.actor(), p)
	if err != nil {
		if !app.IsUserError(err) {
			s.log.Error("create instance failed", "err", err)
		}
		s.renderInstanceForm(w, r, rc, http.StatusBadRequest, p, userMessage(err))
		return
	}
	s.done(w, r, instURL(inst, ""), "Instanz angelegt. Headscale und der Server-Node starten jetzt.")
}

// nodeRow is one row of the device table.
type nodeRow struct {
	N          headscale.Node
	IsGateway  bool
	Mon        monitor.NodeView
	PendingRts []string
	Expired    bool
}

func (s *Server) nodeRows(r *http.Request, rc *reqCtx) ([]nodeRow, error) {
	nodes, err := s.app.Nodes(r.Context(), rc.Inst, 5*time.Second)
	if err != nil {
		return nil, err
	}
	gw := s.app.GatewayNodeID(rc.Inst.ID)
	mv := s.app.Mon.Instance(rc.Inst.ID)
	rows := make([]nodeRow, 0, len(nodes))
	now := time.Now()
	for _, n := range nodes {
		row := nodeRow{N: n, IsGateway: uint64(n.ID) == gw, Mon: mv.Nodes[uint64(n.ID)], Expired: n.Expired(now)}
		for _, rt := range n.AvailableRoutes {
			approved := false
			for _, a := range n.ApprovedRoutes {
				if a == rt {
					approved = true
				}
			}
			if !approved {
				row.PendingRts = append(row.PendingRts, rt)
			}
		}
		rows = append(rows, row)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].IsGateway != rows[j].IsGateway {
			return rows[i].IsGateway
		}
		return ipLess(rows[i].N.IPv4(), rows[j].N.IPv4())
	})
	return rows, nil
}

func ipLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(pb[i])
		if x != y {
			return x < y
		}
	}
	return len(pa) < len(pb)
}

func (s *Server) instanceOverview(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	d := map[string]any{
		"URL":       s.app.Cfg.PublicURL(rc.Inst.Domain),
		"Gateway":   s.app.GW.Status(rc.Inst.ID),
		"HS":        s.app.HS.Status(rc.Inst.ID),
		"Reserved":  app.ReservedIPv4(rc.Inst).String(),
		"Mon":       s.app.Mon.Instance(rc.Inst.ID),
		"SystemUsr": gateway.SystemUser,
	}
	rows, err := s.nodeRows(r, rc)
	if err != nil {
		d["NodesErr"] = userMessage(err)
	}
	d["Nodes"] = rows
	online, total := 0, 0
	for _, x := range rows {
		if x.IsGateway {
			continue
		}
		total++
		if x.N.Online {
			online++
		}
	}
	d["Online"], d["Total"] = online, total
	s.render(w, r, rc, http.StatusOK, "instance", page{Title: rc.Inst.Name, Nav: "dashboard", Tab: "nodes", D: d})
}

func (s *Server) monitorPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	rows, err := s.nodeRows(r, rc)
	d := map[string]any{"Mon": s.app.Mon.Instance(rc.Inst.ID), "Nodes": rows, "Gateway": s.app.GW.Status(rc.Inst.ID)}
	if err != nil {
		d["NodesErr"] = userMessage(err)
	}
	fwds, _ := s.app.DB.ListForwards(r.Context(), rc.Inst.ID)
	type fr struct {
		F   *store.Forward
		Mon monitor.ForwardView
		C   any
	}
	var frs []fr
	snap := s.app.FwdReg.Snapshot()
	for _, f := range fwds {
		frs = append(frs, fr{F: f, Mon: s.app.Mon.Forward(f.ID), C: snap[f.ID]})
	}
	d["Forwards"] = frs
	s.render(w, r, rc, http.StatusOK, "monitor", page{Title: "Monitoring – " + rc.Inst.Name, Nav: "dashboard", Tab: "monitor", D: d})
}

func (s *Server) instanceSettings(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	s.renderInstanceSettings(w, r, rc, http.StatusOK, app.ParamsFromInstance(rc.Inst), nil)
}

func (s *Server) renderInstanceSettings(w http.ResponseWriter, r *http.Request, rc *reqCtx, status int, p app.InstanceParams, f *flash) {
	ctx := r.Context()
	d := map[string]any{
		"P": p, "DERP": s.app.DERPSettings(ctx), "Dir": s.app.InstanceDir(rc.Inst.Slug),
		"Gateway": s.app.GW.Status(rc.Inst.ID), "HS": s.app.HS.Status(rc.Inst.ID), "Reserved": app.ReservedIPv4(rc.Inst).String(),
	}
	if rc.User.IsSuperadmin() {
		d["Users"], _ = s.app.DB.ListUsers(ctx)
	}
	s.render(w, r, rc, status, "instance_settings", page{Title: "Einstellungen – " + rc.Inst.Name, Nav: "dashboard", Tab: "settings", Flash: f, D: d})
}

func (s *Server) instanceSettingsSubmit(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	p := paramsFromForm(r, app.ParamsFromInstance(rc.Inst))
	if !rc.User.IsSuperadmin() {
		p.OwnerID = rc.Inst.OwnerID
	}
	inst := *rc.Inst
	if err := s.app.UpdateInstance(r.Context(), rc.actor(), &inst, p); err != nil {
		if !app.IsUserError(err) {
			s.log.Error("update instance failed", "err", err)
		}
		s.renderInstanceSettings(w, r, rc, http.StatusBadRequest, p, &flash{Kind: "err", Msg: userMessage(err)})
		return
	}
	s.done(w, r, instURL(rc.Inst, "/settings"), "Einstellungen gespeichert.")
}

func (s *Server) instanceState(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	ctx := r.Context()
	var err error
	msg := ""
	switch r.PostFormValue("action") {
	case "start":
		err, msg = s.app.SetInstanceEnabled(ctx, rc.actor(), rc.Inst, true), "Instanz gestartet."
	case "stop":
		err, msg = s.app.SetInstanceEnabled(ctx, rc.actor(), rc.Inst, false), "Instanz gestoppt."
	case "restart":
		err, msg = s.app.RestartInstance(ctx, rc.actor(), rc.Inst), "Instanz wird neu gestartet."
	case "gateway-reset":
		err, msg = s.app.ResetGateway(ctx, rc.actor(), rc.Inst), "Der Server-Node registriert sich neu."
	default:
		err = app.Errf("Unbekannte Aktion")
	}
	if err != nil {
		s.fail(w, r, instURL(rc.Inst, "/settings"), err)
		return
	}
	s.done(w, r, instURL(rc.Inst, "/settings"), msg)
}

func (s *Server) instanceDelete(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if strings.TrimSpace(r.PostFormValue("confirm")) != rc.Inst.Slug {
		s.fail(w, r, instURL(rc.Inst, "/settings"), app.Errf("Zur Bestätigung bitte den Kurznamen %q eingeben", rc.Inst.Slug))
		return
	}
	if err := s.app.DeleteInstance(r.Context(), rc.actor(), rc.Inst); err != nil {
		s.fail(w, r, instURL(rc.Inst, "/settings"), err)
		return
	}
	s.done(w, r, "/", fmt.Sprintf("Instanz %s gelöscht (Daten wurden in den Papierkorb verschoben).", rc.Inst.Name))
}

func (s *Server) instanceLogs(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	lines := s.app.HS.Logs(rc.Inst.ID)
	// newest first
	for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
		lines[i], lines[j] = lines[j], lines[i]
	}
	s.render(w, r, rc, http.StatusOK, "logs", page{Title: "Logs – " + rc.Inst.Name, Nav: "dashboard", Tab: "logs", D: map[string]any{
		"Lines": lines, "HS": s.app.HS.Status(rc.Inst.ID), "Gateway": s.app.GW.Status(rc.Inst.ID),
	}})
}
