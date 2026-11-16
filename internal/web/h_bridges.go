package web

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/testbild-media/openHeadscaleGUI/internal/app"
	"github.com/testbild-media/openHeadscaleGUI/internal/forward"
	"github.com/testbild-media/openHeadscaleGUI/internal/headscale"
	"github.com/testbild-media/openHeadscaleGUI/internal/store"
)

// bridgeInst is an instance with its selectable devices for the forms.
type bridgeInst struct {
	I     *store.Instance
	Nodes []headscale.Node // without the server node
	IPv4  string           // the server's address in this instance (.1)
}

type bridgeRow struct {
	B         *store.Bridge
	From, To  *store.Instance
	Source    string
	Listen    string
	Allowed   []string
	C         forward.Snapshot
	ListenErr string
	TargetErr string
}

// bridgeInstances returns the instances the user may use in bridges.
func (s *Server) bridgeInstances(r *http.Request, rc *reqCtx) []bridgeInst {
	insts, _ := s.app.DB.ListInstances(r.Context(), 0)
	var out []bridgeInst
	for _, i := range insts {
		if !app.CanManage(rc.User, i) {
			continue
		}
		gw := s.app.GatewayNodeID(i.ID)
		var nodes []headscale.Node
		for _, n := range s.app.CachedNodes(i.ID) {
			if uint64(n.ID) != gw && (n.User == nil || n.User.Name != "ohg-system") {
				nodes = append(nodes, n)
			}
		}
		out = append(out, bridgeInst{I: i, Nodes: nodes, IPv4: app.ReservedIPv4(i).String()})
	}
	return out
}

func (s *Server) bridgeRows(r *http.Request, rc *reqCtx, insts []bridgeInst) []bridgeRow {
	byID := map[int64]bridgeInst{}
	for _, i := range insts {
		byID[i.I.ID] = i
	}
	bridges, _ := s.app.DB.ListBridges(r.Context())
	snap := s.app.BridgeReg.Snapshot()
	var rows []bridgeRow
	for _, b := range bridges {
		from, ok1 := byID[b.FromInstanceID]
		to, ok2 := byID[b.ToInstanceID]
		if !ok1 || !ok2 {
			continue // only bridges between instances the user manages
		}
		row := bridgeRow{B: b, From: from.I, To: to.I, C: snap[b.ID],
			Listen: to.IPv4 + ":" + strconv.Itoa(b.ListenPort), ListenErr: s.app.Bridges.RuleError(app.BridgeRule(b))}
		t, err := s.app.BridgeTarget(b)
		row.Source = t
		if b.NodeID != 0 {
			name := "Gerät #" + strconv.FormatInt(b.NodeID, 10)
			for _, n := range from.Nodes {
				if int64(n.ID) == b.NodeID {
					name = n.DisplayName()
				}
			}
			row.Source = name + " (" + t + ")"
		}
		if err != nil {
			row.TargetErr = "Quell-Gerät fehlt"
		}
		if b.AllowAll {
			row.Allowed = []string{"alle Geräte"}
		} else {
			for _, id := range b.AllowedNodes {
				name := "Gerät #" + strconv.FormatInt(id, 10) + " (entfernt)"
				for _, n := range to.Nodes {
					if int64(n.ID) == id {
						name = n.DisplayName()
					}
				}
				row.Allowed = append(row.Allowed, name)
			}
		}
		rows = append(rows, row)
	}
	return rows
}

func (s *Server) bridgesPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	req := app.BridgeRequest{Proto: "tcp", Enabled: true}
	s.renderBridges(w, r, rc, http.StatusOK, req, nil)
}

func (s *Server) renderBridges(w http.ResponseWriter, r *http.Request, rc *reqCtx, status int, req app.BridgeRequest, f *flash) {
	insts := s.bridgeInstances(r, rc)
	// preselect: clients in an isolated instance, the server in another one
	if req.ToInstanceID == 0 && len(insts) > 1 {
		req.ToInstanceID = insts[len(insts)-1].I.ID
		for _, i := range insts {
			if i.I.IsolateClients {
				req.ToInstanceID = i.I.ID
				break
			}
		}
	}
	if req.FromInstanceID == 0 {
		for _, i := range insts {
			if i.I.ID != req.ToInstanceID {
				req.FromInstanceID = i.I.ID
				break
			}
		}
	}
	d := map[string]any{"Insts": insts, "R": req, "Rows": s.bridgeRows(r, rc, insts)}
	s.render(w, r, rc, status, "bridges", page{Title: "Brücken", Nav: "bridges", Flash: f, D: d})
}

func bridgeReq(r *http.Request) app.BridgeRequest {
	from, _ := strconv.ParseInt(r.PostFormValue("from_instance"), 10, 64)
	to, _ := strconv.ParseInt(r.PostFormValue("to_instance"), 10, 64)
	node, _ := strconv.ParseInt(r.PostFormValue("node_id"), 10, 64)
	var allowed []int64
	_ = r.ParseForm()
	for _, v := range r.PostForm["allowed"] {
		if id, err := strconv.ParseInt(v, 10, 64); err == nil {
			allowed = append(allowed, id)
		}
	}
	return app.BridgeRequest{
		Name: r.PostFormValue("name"), FromInstanceID: from, NodeID: node, TargetHost: r.PostFormValue("target_host"),
		TargetPort: formInt(r, "target_port"), Proto: strings.ToLower(r.PostFormValue("proto")), ToInstanceID: to,
		ListenPort: formInt(r, "listen_port"), AllowAll: formBool(r, "allow_all"), AllowedNodes: allowed,
		Enabled: formBool(r, "enabled"),
	}
}

func (s *Server) bridgeCreate(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	req := bridgeReq(r)
	if _, err := s.app.CreateBridge(r.Context(), rc.actor(), req); err != nil {
		if !app.IsUserError(err) && err != app.ErrForbidden {
			s.log.Error("create bridge failed", "err", err)
		}
		s.renderBridges(w, r, rc, http.StatusBadRequest, req, &flash{Kind: "err", Msg: userMessage(err)})
		return
	}
	s.done(w, r, "/bridges", "Brücke angelegt.")
}

func (s *Server) loadBridge(w http.ResponseWriter, r *http.Request, rc *reqCtx) *store.Bridge {
	b, err := s.app.DB.GetBridge(r.Context(), pathInt(r, "bid"))
	if err != nil || !s.app.CanManageBridge(r.Context(), rc.actor(), b) {
		s.notFound(w, r, rc)
		return nil
	}
	return b
}

func (s *Server) bridgeEdit(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	b := s.loadBridge(w, r, rc)
	if b == nil {
		return
	}
	s.renderBridgeEdit(w, r, rc, http.StatusOK, b, app.BridgeRequestFrom(b), nil)
}

func (s *Server) renderBridgeEdit(w http.ResponseWriter, r *http.Request, rc *reqCtx, status int, b *store.Bridge, req app.BridgeRequest, f *flash) {
	insts := s.bridgeInstances(r, rc)
	d := map[string]any{"B": b, "Insts": insts, "R": req, "C": s.app.BridgeReg.Get(b.ID).Snapshot()}
	s.render(w, r, rc, status, "bridge_edit", page{Title: "Brücke bearbeiten", Nav: "bridges", Flash: f, D: d})
}

func (s *Server) bridgeAction(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	b := s.loadBridge(w, r, rc)
	if b == nil {
		return
	}
	ctx := r.Context()
	switch r.PathValue("action") {
	case "update":
		req := bridgeReq(r)
		cp := *b
		if err := s.app.UpdateBridge(ctx, rc.actor(), &cp, req); err != nil {
			s.renderBridgeEdit(w, r, rc, http.StatusBadRequest, b, req, &flash{Kind: "err", Msg: userMessage(err)})
			return
		}
		s.done(w, r, "/bridges", "Brücke gespeichert.")
	case "toggle":
		if err := s.app.SetBridgeEnabled(ctx, rc.actor(), b, !b.Enabled); err != nil {
			s.fail(w, r, "/bridges", err)
			return
		}
		s.done(w, r, "/bridges", map[bool]string{true: "Brücke aktiviert.", false: "Brücke deaktiviert."}[b.Enabled])
	case "delete":
		if err := s.app.DeleteBridge(ctx, rc.actor(), b); err != nil {
			s.fail(w, r, "/bridges", err)
			return
		}
		s.done(w, r, "/bridges", "Brücke gelöscht.")
	default:
		s.notFound(w, r, rc)
	}
}
