package web

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/testbild-media/openHeadscaleGUI/internal/app"
	"github.com/testbild-media/openHeadscaleGUI/internal/headscale"
	"github.com/testbild-media/openHeadscaleGUI/internal/store"
)

func TestTemplatesParse(t *testing.T) {
	tpl, err := loadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"login", "dashboard", "instance", "node", "pending", "clients", "forwards",
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
	out := render(app.ForwardRequest{Kind: "http", Local: true, TargetHost: "127.0.0.1", TargetPort: 9000}, true)
	for _, want := range []string{`<option value="local" selected>`, `value="127.0.0.1" placeholder="127.0.0.1"`} {
		if !strings.Contains(out, want) {
			t.Errorf("local forward form: missing %q", want)
		}
	}
	if strings.Contains(out, `value="0" selected`) || strings.Contains(out, `value="7" selected`) {
		t.Error("local forward: other target selected")
	}
	if strings.Contains(render(app.ForwardRequest{Kind: "http"}, false), `value="local"`) {
		t.Error("local target offered to a normal user")
	}
	if strings.Contains(render(app.ForwardRequest{Kind: "http"}, true), `value="redirect"`) {
		t.Error("redirect type still offered in the forward form")
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
