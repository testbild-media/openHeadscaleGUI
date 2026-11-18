package web

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/testbild-media/openHeadscaleGUI/internal/app"
	"github.com/testbild-media/openHeadscaleGUI/internal/fwsync"
	"github.com/testbild-media/openHeadscaleGUI/internal/headscale"
	"github.com/testbild-media/openHeadscaleGUI/internal/store"
)

func TestTemplatesParse(t *testing.T) {
	tpl, err := loadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"login", "dashboard", "instance", "node", "pending", "clients", "forwards", "server_forwards", "forward_edit",
		"monitor", "derp", "users", "settings", "audit", "profile", "twofa", "policy", "logs"} {
		if tpl.pages[name] == nil {
			t.Errorf("template %s missing", name)
		}
	}
	if !strings.Contains(funcs["asset"].(func(string) string)("app.css"), "?v=") {
		t.Error("static assets are not versioned")
	}
}

func TestSparklineOnlyNumbers(t *testing.T) {
	out := string(sparkline([]float64{1, 2, math.NaN(), 4}, `x" onload="alert(1)`))
	if strings.Contains(out, `onload="`) {
		t.Fatal("class attribute not escaped")
	}
	if !strings.Contains(out, "<polyline") || !strings.Contains(out, `class="gap"`) {
		t.Fatalf("unexpected svg: %s", out)
	}
}

func TestSafeNext(t *testing.T) {
	for in, want := range map[string]string{
		"/i/1":              "/i/1",
		"//evil.example":    "/",
		"https://evil.test": "/",
		"/\\evil":           "/",
		"":                  "/",
	} {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestConnectCommands(t *testing.T) {
	tpl, err := loadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	data := dict("URL", "https://vpn1.example.com", "Key", "hskey-auth-x", "Exit", true, "Routes", "192.168.1.0/24")
	if err := tpl.pages["clients"].ExecuteTemplate(&sb, "connect", data); err != nil {
		t.Fatal(err)
	}
	out := sb.String()
	for _, want := range []string{
		"sudo tailscale up --reset --force-reauth --accept-routes --login-server https://vpn1.example.com --authkey hskey-auth-x --advertise-exit-node --advertise-routes=192.168.1.0/24",
		`id="cmd-win">tailscale up --reset --force-reauth --accept-routes --login-server https://vpn1.example.com --authkey hskey-auth-x`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestClientsKeyButtons(t *testing.T) {
	tpl, err := loadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	key := &headscale.PreAuthKey{ID: 5, Key: "hskey-auth-abc", Reusable: true}
	prof := &store.ClientProfile{ID: 3, Name: "nas", PreAuthKeyID: 5, AutoExit: true}
	data := map[string]any{"CSRF": "tok", "Inst": &store.Instance{ID: 1}, "D": map[string]any{
		"URL": "https://vpn1.example.com", "Now": time.Now(), "Created": profileCreated(prof, key),
		"Keys": []headscale.PreAuthKey{*key, {ID: 6}}, "Stored": map[headscale.U64]bool{5: true},
		"Profiles": []*store.ClientProfile{prof}, "ProfileKey": map[int64]bool{3: true},
	}}
	var sb strings.Builder
	if err := tpl.pages["clients"].ExecuteTemplate(&sb, "content", data); err != nil {
		t.Fatal(err)
	}
	out := sb.String()
	for _, want := range []string{"/i/1/keys/5/show", "/i/1/profiles/3/showkey", "/i/1/profiles/3/newkey",
		"--authkey hskey-auth-abc --advertise-exit-node", "Anmeldung für Client „nas“"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(out, "/i/1/keys/6/show") {
		t.Error("show button for a key without stored copy")
	}
}

func TestForwardTargetSelect(t *testing.T) {
	tpl, err := loadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	nodes := []headscale.Node{
		{ID: 1, GivenName: "ohg-gateway", IPAddresses: []string{"100.100.0.1"}},
		{ID: 7, GivenName: "homeassistant", IPAddresses: []string{"100.100.0.7"}},
		{ID: 9, GivenName: "nas", IPAddresses: []string{"100.100.0.9"}},
	}
	render := func(nodeID int64) string {
		var sb strings.Builder
		d := map[string]any{"R": app.ForwardRequest{Kind: "http", NodeID: nodeID, TargetPort: 8123}, "Nodes": nodes,
			"GatewayID": uint64(1), "PortMin": 20000, "PortMax": 29999}
		if err := tpl.pages["forward_edit"].ExecuteTemplate(&sb, "fwdfields", d); err != nil {
			t.Fatal(err)
		}
		return sb.String()
	}
	// editing a forward bound to a device: that device is selected
	out := render(7)
	if !strings.Contains(out, `<option value="7" selected>homeassistant (100.100.0.7)</option>`) {
		t.Errorf("bound device not selected:\n%s", out)
	}
	if strings.Contains(out, `value="0" selected`) || strings.Contains(out, `value="9" selected`) {
		t.Error("wrong option selected")
	}
	if strings.Contains(out, "ohg-gateway") {
		t.Error("gateway offered as target")
	}
	// new forward: only "own IP" is preselected
	out = render(0)
	if !strings.Contains(out, `value="0" selected`) || strings.Contains(out, `value="7" selected`) {
		t.Errorf("new form preselects a device:\n%s", out)
	}
}

func TestToInt64NamedTypes(t *testing.T) {
	if toInt64(headscale.U64(42)) != 42 || toInt64(uint64(3)) != 3 || toInt64(int(5)) != 5 || toInt64(nil) != 0 || toInt64("x") != 0 {
		t.Error("toInt64 conversion wrong")
	}
}

func TestForwardFormLocalAndRedirect(t *testing.T) {
	tpl, err := loadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	render := func(r app.ForwardRequest, super bool) string {
		var sb strings.Builder
		d := map[string]any{"R": r, "Super": super, "GatewayID": uint64(1), "PortMin": 20000, "PortMax": 29999,
			"Nodes": []headscale.Node{{ID: 7, GivenName: "nas", IPAddresses: []string{"100.64.0.7"}}}}
		if err := tpl.pages["forward_edit"].ExecuteTemplate(&sb, "fwdfields", d); err != nil {
			t.Fatal(err)
		}
		return sb.String()
	}
	// forwards of an instance never target the server itself; superadmins
	// get a pointer to the server forwards instead
	out := render(app.ForwardRequest{Kind: "http"}, true)
	if strings.Contains(out, `value="local"`) || !strings.Contains(out, `href="/server-forwards"`) {
		t.Errorf("instance form for superadmins:\n%s", out)
	}
	if out := render(app.ForwardRequest{Kind: "http"}, false); strings.Contains(out, `value="local"`) || strings.Contains(out, "/server-forwards") {
		t.Error("normal user: local target or server forwards offered")
	}
	if strings.Contains(out, `value="redirect"`) {
		t.Error("redirect type still offered in the forward form")
	}
	// server forward: only an address on the server, no device selection
	var sb strings.Builder
	d := map[string]any{"R": app.ForwardRequest{Kind: "tcp", Local: true, TargetHost: "172.17.0.2", TargetPort: 25565, PublicPort: 25565},
		"Server": true, "Super": true, "PortMin": 20000, "PortMax": 29999}
	if err := tpl.pages["server_forwards"].ExecuteTemplate(&sb, "fwdfields", d); err != nil {
		t.Fatal(err)
	}
	out = sb.String()
	for _, want := range []string{`<input type="hidden" name="node_id" value="local">`, `name="target_host" value="172.17.0.2"`,
		`name="target_port" value="25565"`, `<option value="tcp" selected>`} {
		if !strings.Contains(out, want) {
			t.Errorf("server forward form: missing %q", want)
		}
	}
	if strings.Contains(out, `<select name="node_id"`) {
		t.Error("server forward form offers devices")
	}
}

func TestServerForwardsPage(t *testing.T) {
	tpl, err := loadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	rows := []fwdRow{
		{F: &store.Forward{ID: 5, Kind: "http", Domain: "os.example.com", LocalTarget: true, TargetHost: "127.0.0.1", TargetPort: 8080, Enabled: true},
			Target: "Dieser Server (127.0.0.1:8080)", URL: "https://os.example.com"},
		{F: &store.Forward{ID: 6, Kind: "tcp", PublicPort: 25565, LocalTarget: true, TargetHost: "127.0.0.1", TargetPort: 25565, Enabled: true},
			Target: "Dieser Server (127.0.0.1:25565)", FW: fwsync.PortStatus{State: fwsync.StateOpened}},
	}
	p := page{Title: "Server-Freigaben", Nav: "server-forwards", Brand: "OpenHeadscaleGUI", CSRF: "tok",
		User: &store.User{Username: "root", Role: store.RoleSuperadmin},
		D: map[string]any{"Rows": rows, "R": app.ForwardRequest{Kind: "http", Local: true, TargetHost: "127.0.0.1", Enabled: true},
			"Base": "/server-forwards", "Server": true, "Super": true, "PortMin": 20000, "PortMax": 29999,
			"FW": app.FirewallView{Installed: true}}}
	var sb strings.Builder
	if err := tpl.pages["server_forwards"].ExecuteTemplate(&sb, "layout", p); err != nil {
		t.Fatal(err)
	}
	out := sb.String()
	for _, want := range []string{
		`<a href="/server-forwards" class="active">`, // navigation entry
		`<h1>Server-Freigaben</h1>`, `href="/server-forwards/5"`, `action="/server-forwards/6/toggle"`,
		`action="/server-forwards/6/delete" data-confirm="Server-Freigabe löschen?"`, `<form method="post" action="/server-forwards" class="card mt">`,
		`Dieser Server (127.0.0.1:25565)`, `Server-Firewall offen`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("server forwards page: missing %q", want)
		}
	}
	if strings.Contains(out, "/i/") {
		t.Error("server forwards page links into an instance")
	}
	// normal users do not see the entry
	p.User = &store.User{Username: "anna", Role: store.RoleUser}
	sb.Reset()
	if err := tpl.pages["redirects"].ExecuteTemplate(&sb, "layout", page{Title: "x", Brand: "x", User: p.User, D: map[string]any{}}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sb.String(), "/server-forwards") {
		t.Error("server forwards offered to a normal user")
	}
}

func TestRedirectForm(t *testing.T) {
	tpl, err := loadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	d := map[string]any{"R": app.RedirectRequest{Domain: "alt.example.com", URL: "https://www.example.org", Code: 301, KeepPath: true, Enabled: true},
		"Suffixes": []string{"example.com"}}
	if err := tpl.pages["redirects"].ExecuteTemplate(&sb, "redirectfields", d); err != nil {
		t.Fatal(err)
	}
	out := sb.String()
	for _, want := range []string{`name="domain" value="alt.example.com"`, `name="url" value="https://www.example.org"`,
		`<option value="301" selected>`, `name="keep_path" value="1" checked`, `Erlaubt: example.com`} {
		if !strings.Contains(out, want) {
			t.Errorf("redirect form: missing %q", want)
		}
	}
}

func TestSiteName(t *testing.T) {
	for in, want := range map[string]string{"": "oh", "OpenHeadscaleGUI": "oh", "Walzwerk VPN": "wv", "Emily-Net": "em",
		"walzwerk": "wa", "  Ä b": "äb", "1&1 Netz": "1n", "!!": "oh"} {
		if got := initials(in); got != want {
			t.Errorf("initials(%q) = %q, want %q", in, got, want)
		}
	}
	tpl, err := loadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	if err := tpl.pages["login"].ExecuteTemplate(&sb, "layout", page{Title: "Anmelden", Bare: true, Brand: "Walzwerk <VPN>", D: map[string]any{}}); err != nil {
		t.Fatal(err)
	}
	out := sb.String()
	for _, want := range []string{"<title>Anmelden · Walzwerk &lt;VPN&gt;</title>", `<span class="logo">wv</span>`, "Walzwerk &lt;VPN&gt;</span>"} {
		if !strings.Contains(out, want) {
			t.Errorf("login page: missing %q", want)
		}
	}
}

func TestBridgeFormModes(t *testing.T) {
	tpl, err := loadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	insts := []bridgeInst{
		{I: &store.Instance{ID: 1, Name: "Systeme"}, IPv4: "100.64.0.1",
			Nodes: []headscale.Node{{ID: 2, GivenName: "server-a", IPAddresses: []string{"100.64.0.2"}}}},
		{I: &store.Instance{ID: 2, Name: "Personen"}, IPv4: "100.100.0.1",
			Nodes: []headscale.Node{{ID: 2, GivenName: "anna", IPAddresses: []string{"100.100.0.2"}}}},
	}
	render := func(r app.BridgeRequest) string {
		var sb strings.Builder
		if err := tpl.pages["bridges"].ExecuteTemplate(&sb, "bridgefields", map[string]any{"Insts": insts, "R": r}); err != nil {
			t.Fatal(err)
		}
		return sb.String()
	}
	out := render(app.BridgeRequest{Mode: "host", FromInstanceID: 1, NodeID: 2, ToInstanceID: 2, AllowedNodes: []int64{2},
		VirtualIP: "198.18.0.1", DNSName: "server-a"})
	for _, want := range []string{`<option value="host" selected>`, `name="dns_name" value="server-a"`, `name="virtual_ip" value="198.18.0.1"`,
		`data-show-for="mode:port"`, `name="allowed" value="2" checked`} {
		if !strings.Contains(out, want) {
			t.Errorf("host bridge form: missing %q", want)
		}
	}
	out = render(app.BridgeRequest{Mode: "port", FromInstanceID: 1, NodeID: 2, ToInstanceID: 2, Proto: "udp", TargetPort: 53, ListenPort: 5353})
	for _, want := range []string{`<option value="port" selected>`, `<option value="udp" selected>`, `name="listen_port" value="5353"`} {
		if !strings.Contains(out, want) {
			t.Errorf("port bridge form: missing %q", want)
		}
	}
}

func TestRelayAndUDPWarnings(t *testing.T) {
	tpl, err := loadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	exec := func(page, name string, data any) string {
		var sb strings.Builder
		if err := tpl.pages[page].ExecuteTemplate(&sb, name, data); err != nil {
			t.Fatal(err)
		}
		return sb.String()
	}
	udp := app.UDPCheck{Known: true, Blocked4: true, Clients4: 2, Since: time.Now().Add(-10 * time.Minute),
		STUNPort: 3478, GatewayPorts: "41641–41642"}
	out := exec("derp", "udpwarn", udp)
	for _, want := range []string{"Von außen kommt kein UDP an (IPv4)", "2 Geräte nutzen den Relay", "UDP 3478",
		"<b>3478</b> (STUN)", "<b>41641–41642</b> (Server-Knoten"} {
		if !strings.Contains(out, want) {
			t.Errorf("UDP warning: missing %q in:\n%s", want, out)
		}
	}
	if strings.TrimSpace(exec("derp", "udpwarn", app.UDPCheck{Known: true})) != "" {
		t.Error("warning shown although UDP arrives")
	}
	out = exec("derp", "relayissues", []app.RelayIssue{{InstanceID: 1, Instance: "Walzwerk System", NodeID: 2,
		Node: "opensignage", Since: time.Now().Add(-5 * time.Minute)}})
	for _, want := range []string{"1 Gerät ist online, aber nicht mit dem Relay verbunden", `href="/i/1/nodes/2">opensignage</a>`,
		"Walzwerk System", "sudo systemctl restart tailscaled"} {
		if !strings.Contains(out, want) {
			t.Errorf("relay issues: missing %q in:\n%s", want, out)
		}
	}
	if strings.TrimSpace(exec("derp", "relayissues", []app.RelayIssue(nil))) != "" {
		t.Error("relay issue box without issues")
	}
}

func TestDERPAddrHelp(t *testing.T) {
	tpl, err := loadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	render := func(a, src, autoErr string) string {
		var sb strings.Builder
		d := dict("A", a, "Src", src, "Auto", struct{ Err string }{autoErr})
		if err := tpl.pages["derp"].ExecuteTemplate(&sb, "derpaddr", d); err != nil {
			t.Fatal(err)
		}
		return sb.String()
	}
	for _, c := range []struct{ a, src, err, want string }{
		{"85.215.175.236", "automatisch", "", `automatisch aus DNS: <span class="mono">85.215.175.236</span>`},
		{"203.0.114.7", "manuell", "", `eingetragen: <span class="mono">203.0.114.7</span>`},
		{"none", "manuell", "", "nicht verwendet"},
		{"", "", "die Domain löst nur auf nicht öffentliche Adressen auf", "nicht ermittelt (die Domain löst nur auf nicht öffentliche Adressen auf)"},
		{"", "", "", "keine – Geräte lösen die Domain selbst auf"},
	} {
		if out := render(c.a, c.src, c.err); !strings.Contains(out, c.want) {
			t.Errorf("%+v: got %q", c, out)
		}
	}
}

func TestFirewallState(t *testing.T) {
	tpl, err := loadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	render := func(s fwsync.PortStatus, v app.FirewallView) string {
		var sb strings.Builder
		if err := tpl.pages["forwards"].ExecuteTemplate(&sb, "fwstate", dict("S", s, "V", v)); err != nil {
			t.Fatal(err)
		}
		return sb.String()
	}
	inst := app.FirewallView{Installed: true}
	for _, c := range []struct {
		s    fwsync.PortStatus
		v    app.FirewallView
		want string
	}{
		{fwsync.PortStatus{State: fwsync.StateOpened}, inst, "Server-Firewall offen"},
		{fwsync.PortStatus{State: fwsync.StateExisting}, inst, "(eigene Regel)"},
		{fwsync.PortStatus{State: fwsync.StateNoFirewall}, inst, "keine Server-Firewall aktiv"},
		{fwsync.PortStatus{State: fwsync.StateNotListening}, inst, "ohg lauscht nicht"},
		{fwsync.PortStatus{State: fwsync.StateForeign}, inst, "eigene eingeschränkte Regel"},
		{fwsync.PortStatus{State: fwsync.StateRefused, Detail: "Ports unter 1024 öffnet ohg nie"}, inst, "Ports unter 1024"},
		{fwsync.PortStatus{State: fwsync.StateError, Detail: "ERROR: boom"}, inst, "Fehler – ERROR: boom"},
		{fwsync.PortStatus{}, inst, "wird geöffnet"},
		{fwsync.PortStatus{}, app.FirewallView{Installed: true, Pending: true, Stale: true}, "Automatik reagiert nicht"},
		{fwsync.PortStatus{}, app.FirewallView{}, "Automatik nicht installiert"},
	} {
		if out := render(c.s, c.v); !strings.Contains(out, c.want) {
			t.Errorf("%+v: missing %q in %q", c.s, c.want, out)
		}
	}
}
