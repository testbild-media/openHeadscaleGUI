package headscale

import (
	"encoding/json"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestRenderConfig(t *testing.T) {
	b, err := RenderConfig(ConfigParams{
		Dir: "/var/lib/ohg/instances/x", ServerURL: "https://vpn.example.com", Port: 42000,
		PrefixV4: "100.64.0.0/10", PrefixV6: "fd7a:115c:a1e0::/48", Allocation: "sequential",
		MagicDNS: true, BaseDomain: "x.internal", Nameservers: []string{"1.1.1.1"},
		UseCentralDERP: true, UsePublicDERP: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := yaml.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m["listen_addr"] != "127.0.0.1:42000" {
		t.Errorf("listen_addr = %v", m["listen_addr"])
	}
	if m["metrics_listen_addr"] != "" {
		t.Error("metrics must be disabled")
	}
	if m["unix_socket"] != "headscale.sock" {
		t.Error("socket path must be relative to the instance dir")
	}
	derp := m["derp"].(map[string]any)
	if paths := derp["paths"].([]any); len(paths) != 1 || paths[0] != "derpmap.yaml" {
		t.Errorf("derp paths = %v", paths)
	}
	if urls := derp["urls"].([]any); len(urls) != 0 {
		t.Errorf("public DERP must be off: %v", urls)
	}
	if !strings.Contains(string(b), "unix_socket: headscale.sock") {
		t.Error("windows per-run socket replacement relies on this exact line")
	}
}

func TestU64(t *testing.T) {
	var n Node
	if err := json.Unmarshal([]byte(`{"id":"42","ipAddresses":["100.64.0.5","fd7a::5"],"preAuthKey":{"id":7}}`), &n); err != nil {
		t.Fatal(err)
	}
	if n.ID != 42 || n.PreAuthKey.ID != 7 || n.IPv4() != "100.64.0.5" || n.IPv6() != "fd7a::5" {
		t.Errorf("decoded %+v", n)
	}
}

func TestFirstHost(t *testing.T) {
	a, err := FirstHost("100.64.0.0/10")
	if err != nil || a.String() != "100.64.0.1" {
		t.Errorf("got %v %v", a, err)
	}
}
