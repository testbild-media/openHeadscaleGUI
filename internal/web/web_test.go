package web

import (
	"math"
	"strings"
	"testing"
	"time"

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
