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
		"sudo tailscale up --reset --force-reauth --login-server https://vpn1.example.com --authkey hskey-auth-x --advertise-exit-node --advertise-routes=192.168.1.0/24",
		`id="cmd-win">tailscale up --reset --force-reauth --login-server https://vpn1.example.com --authkey hskey-auth-x`,
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
