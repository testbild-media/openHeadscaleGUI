package headscale

import (
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// ConfigParams contains everything needed to render a headscale config.
type ConfigParams struct {
	Dir              string // instance directory
	ServerURL        string // https://vpn.example.com
	Port             int    // loopback port
	PrefixV4         string
	PrefixV6         string
	Allocation       string
	MagicDNS         bool
	BaseDomain       string
	Nameservers      []string
	OverrideLocalDNS bool
	UseCentralDERP   bool
	UsePublicDERP    bool
	NodeExpiry       string
	EphemeralTimeout string
	LogLevel         string
}

// Paths of the files inside an instance directory.
func ConfigPath(dir string) string  { return filepath.Join(dir, "config.yaml") }
func DBPath(dir string) string      { return filepath.Join(dir, "db.sqlite") }
func DERPMapPath(dir string) string { return filepath.Join(dir, "derpmap.yaml") }
func SocketPath(dir string) string  { return filepath.Join(dir, "headscale.sock") }
func GatewayDir(dir string) string  { return filepath.Join(dir, "gateway") }

// RenderConfig renders the headscale config.yaml.
func RenderConfig(p ConfigParams) ([]byte, error) {
	nameservers := p.Nameservers
	if nameservers == nil {
		nameservers = []string{}
	}
	derpURLs := []string{}
	derpPaths := []string{}
	if p.UsePublicDERP {
		derpURLs = append(derpURLs, "https://controlplane.tailscale.com/derpmap/default")
	}
	if p.UseCentralDERP {
		derpPaths = append(derpPaths, DERPMapPath(p.Dir))
	}
	level := p.LogLevel
	if level == "" {
		level = "info"
	}
	expiry := p.NodeExpiry
	if expiry == "" {
		expiry = "0"
	}
	ephemeral := p.EphemeralTimeout
	if ephemeral == "" {
		ephemeral = "30m"
	}
	cfg := map[string]any{
		"server_url":          p.ServerURL,
		"listen_addr":         "127.0.0.1:" + itoa(p.Port),
		"metrics_listen_addr": "",
		"grpc_listen_addr":    "127.0.0.1:0",
		"grpc_allow_insecure": false,
		// Requests come from the ohg edge on loopback, which sets
		// X-Forwarded-For to the real client address.
		"trusted_proxies": []string{"127.0.0.1/32", "::1/128"},
		"noise": map[string]any{
			"private_key_path": filepath.Join(p.Dir, "noise_private.key"),
		},
		"prefixes": map[string]any{
			"v4":         p.PrefixV4,
			"v6":         p.PrefixV6,
			"allocation": p.Allocation,
		},
		"derp": map[string]any{
			"server": map[string]any{
				"enabled": false,
			},
			"urls":                derpURLs,
			"paths":               derpPaths,
			"auto_update_enabled": p.UsePublicDERP,
			"update_frequency":    "3h",
		},
		"disable_check_updates": true,
		"node": map[string]any{
			"expiry": expiry,
			"ephemeral": map[string]any{
				"inactivity_timeout": ephemeral,
			},
		},
		"database": map[string]any{
			"type": "sqlite",
			"sqlite": map[string]any{
				"path":              DBPath(p.Dir),
				"write_ahead_log":   true,
				"wal_autocheckpoint": 1000,
			},
		},
		"tls_cert_path":            "",
		"tls_key_path":             "",
		"tls_letsencrypt_hostname": "",
		"log": map[string]any{
			"level":  level,
			"format": "text",
		},
		"policy": map[string]any{
			"mode": "database",
		},
		"dns": map[string]any{
			"magic_dns":          p.MagicDNS,
			"base_domain":        p.BaseDomain,
			"override_local_dns": p.OverrideLocalDNS && len(nameservers) > 0,
			"nameservers": map[string]any{
				"global": nameservers,
				"split":  map[string]any{},
			},
			"search_domains": []string{},
			"extra_records":  []any{},
		},
		"unix_socket":            SocketPath(p.Dir),
		"unix_socket_permission": "0770",
		"logtail": map[string]any{
			"enabled": false,
		},
		"taildrop": map[string]any{
			"enabled": true,
		},
	}
	return yaml.Marshal(cfg)
}

// DERPNode describes the central DERP server for the generated DERP map.
type DERPNode struct {
	RegionID   int
	RegionCode string
	RegionName string
	Hostname   string
	IPv4       string
	IPv6       string
	STUNPort   int
	DERPPort   int
}

// RenderDERPMap renders the derpmap.yaml containing the central DERP region.
func RenderDERPMap(n DERPNode) ([]byte, error) {
	node := map[string]any{
		"name":     itoa(n.RegionID) + "a",
		"regionid": n.RegionID,
		"hostname": n.Hostname,
		"stunport": n.STUNPort,
		"stunonly": false,
		"derpport": n.DERPPort,
	}
	if n.IPv4 != "" {
		node["ipv4"] = n.IPv4
	}
	if n.IPv6 != "" {
		node["ipv6"] = n.IPv6
	}
	m := map[string]any{
		"regions": map[int]any{
			n.RegionID: map[string]any{
				"regionid":   n.RegionID,
				"regioncode": n.RegionCode,
				"regionname": n.RegionName,
				"nodes":      []any{node},
			},
		},
	}
	return yaml.Marshal(m)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
