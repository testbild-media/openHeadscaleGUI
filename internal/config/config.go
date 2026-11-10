// Package config loads the runtime configuration of ohg from environment
// variables, optionally pre-populated from an env file (KEY=VALUE lines).
package config

import (
	"bufio"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// DefaultEnvFile is read (if it exists) before evaluating the environment.
// Variables that are already set in the process environment win.
const DefaultEnvFile = "/etc/ohg/ohg.env"

// TLS modes.
const (
	TLSModeACME       = "acme"
	TLSModeSelfSigned = "selfsigned"
	TLSModeOff        = "off"
)

// Config is the process configuration. Everything that can be changed at
// runtime lives in the database (settings table) instead.
type Config struct {
	DataDir       string
	AdminDomain   string
	ACMEEmail     string
	ACMEDirectory string
	TLSMode       string
	HTTPAddr      string
	HTTPSAddr     string
	HeadscaleBin  string

	// AdminAllowCIDRs restricts access to the admin GUI (empty = everyone).
	AdminAllowCIDRs []netip.Prefix
	// TrustedProxies are allowed to set X-Forwarded-For (empty = none).
	TrustedProxies []netip.Prefix

	PublicIPv4 string
	PublicIPv6 string

	// InternalPortBase is the first loopback port used for headscale
	// instances (each instance gets one port).
	InternalPortBase int
	// GatewayPortBase is the first UDP port used by the embedded
	// tailscale gateways for WireGuard (each instance gets one port).
	GatewayPortBase int

	SessionIdle time.Duration
	SessionMax  time.Duration
	Require2FA  bool
	Dev         bool
	LogLevel    string
}

// LoadEnvFile reads KEY=VALUE pairs from path and sets them in the process
// environment unless they are already set. Missing files are ignored.
func LoadEnvFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
			v = v[1 : len(v)-1]
		}
		if _, exists := os.LookupEnv(k); !exists {
			os.Setenv(k, v)
		}
	}
	return sc.Err()
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return def
}

func envBool(key string, def bool) bool {
	v := strings.ToLower(env(key, ""))
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return def
}

func envInt(key string, def int) (int, error) {
	v := env(key, "")
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return n, nil
}

func envDuration(key string, def time.Duration) (time.Duration, error) {
	v := env(key, "")
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return d, nil
}

// ParsePrefixes parses a comma separated list of CIDRs or single IPs.
func ParsePrefixes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == ';' }) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "/") {
			p, err := netip.ParsePrefix(part)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q", part)
			}
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(part)
		if err != nil {
			return nil, fmt.Errorf("invalid IP %q", part)
		}
		out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
	}
	return out, nil
}

// Load builds the configuration from the environment.
func Load() (*Config, error) {
	c := &Config{
		DataDir:       env("OHG_DATA_DIR", "/var/lib/ohg"),
		AdminDomain:   strings.ToLower(env("OHG_ADMIN_DOMAIN", "")),
		ACMEEmail:     env("OHG_ACME_EMAIL", ""),
		ACMEDirectory: env("OHG_ACME_DIRECTORY", "https://acme-v02.api.letsencrypt.org/directory"),
		TLSMode:       strings.ToLower(env("OHG_TLS_MODE", TLSModeACME)),
		HTTPAddr:      env("OHG_HTTP_ADDR", ":80"),
		HTTPSAddr:     env("OHG_HTTPS_ADDR", ":443"),
		HeadscaleBin:  env("OHG_HEADSCALE_BIN", "/usr/local/lib/ohg/headscale"),
		PublicIPv4:    env("OHG_PUBLIC_IPV4", ""),
		PublicIPv6:    env("OHG_PUBLIC_IPV6", ""),
		Require2FA:    envBool("OHG_REQUIRE_2FA", false),
		Dev:           envBool("OHG_DEV", false),
		LogLevel:      strings.ToLower(env("OHG_LOG_LEVEL", "info")),
	}
	var err error
	if c.AdminAllowCIDRs, err = ParsePrefixes(env("OHG_ADMIN_ALLOW_CIDRS", "")); err != nil {
		return nil, fmt.Errorf("OHG_ADMIN_ALLOW_CIDRS: %w", err)
	}
	if c.TrustedProxies, err = ParsePrefixes(env("OHG_TRUSTED_PROXIES", "")); err != nil {
		return nil, fmt.Errorf("OHG_TRUSTED_PROXIES: %w", err)
	}
	if c.InternalPortBase, err = envInt("OHG_INTERNAL_PORT_BASE", 42000); err != nil {
		return nil, err
	}
	if c.GatewayPortBase, err = envInt("OHG_GATEWAY_PORT_BASE", 41641); err != nil {
		return nil, err
	}
	if c.SessionIdle, err = envDuration("OHG_SESSION_IDLE", 30*time.Minute); err != nil {
		return nil, err
	}
	if c.SessionMax, err = envDuration("OHG_SESSION_MAX", 12*time.Hour); err != nil {
		return nil, err
	}
	if c.PublicIPv4 != "" {
		if a, err := netip.ParseAddr(c.PublicIPv4); err != nil || !a.Is4() {
			return nil, fmt.Errorf("OHG_PUBLIC_IPV4 is not a valid IPv4 address")
		}
	}
	if c.PublicIPv6 != "" {
		if a, err := netip.ParseAddr(c.PublicIPv6); err != nil || !a.Is6() {
			return nil, fmt.Errorf("OHG_PUBLIC_IPV6 is not a valid IPv6 address")
		}
	}
	switch c.TLSMode {
	case TLSModeACME, TLSModeSelfSigned, TLSModeOff:
	default:
		return nil, fmt.Errorf("OHG_TLS_MODE must be acme, selfsigned or off")
	}
	if c.DataDir, err = filepath.Abs(c.DataDir); err != nil {
		return nil, err
	}
	return c, nil
}

// ValidateForServe performs checks that are only required for the server.
func (c *Config) ValidateForServe() error {
	if c.AdminDomain == "" {
		return errors.New("OHG_ADMIN_DOMAIN must be set (e.g. admin.example.com)")
	}
	if c.TLSMode == TLSModeACME && c.ACMEEmail == "" {
		return errors.New("OHG_ACME_EMAIL must be set when OHG_TLS_MODE=acme")
	}
	if c.InternalPortBase < 1024 || c.InternalPortBase > 60000 {
		return errors.New("OHG_INTERNAL_PORT_BASE must be between 1024 and 60000")
	}
	if c.GatewayPortBase < 1024 || c.GatewayPortBase > 60000 {
		return errors.New("OHG_GATEWAY_PORT_BASE must be between 1024 and 60000")
	}
	return nil
}

// SecureCookies reports whether cookies must carry the Secure attribute.
func (c *Config) SecureCookies() bool { return !c.PlainHTTP() }

// PlainHTTP reports whether ohg itself is reached via plain HTTP (TLS mode
// "off" together with OHG_DEV). Without OHG_DEV, TLS mode "off" assumes an
// external TLS terminating proxy on port 443.
func (c *Config) PlainHTTP() bool { return c.TLSMode == TLSModeOff && c.Dev }

// AdminURL returns the base URL of the admin GUI.
func (c *Config) AdminURL() string { return c.PublicURL(c.AdminDomain) }

// PublicURL builds the externally visible URL for a domain served by the edge.
func (c *Config) PublicURL(domain string) string {
	port := c.HTTPSPort()
	if c.PlainHTTP() {
		if port == 80 {
			return "http://" + domain
		}
		return "http://" + domain + ":" + strconv.Itoa(port)
	}
	if port == 443 {
		return "https://" + domain
	}
	return "https://" + domain + ":" + strconv.Itoa(port)
}

// HTTPSPort returns the externally used port for HTTPS (or HTTP in dev).
func (c *Config) HTTPSPort() int {
	addr, def := c.HTTPSAddr, 443
	switch {
	case c.PlainHTTP():
		addr, def = c.HTTPAddr, 80
	case c.TLSMode == TLSModeOff:
		return 443
	}
	_, p, err := splitPort(addr)
	if err != nil || p == "" {
		return def
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		return def
	}
	return n
}

func splitPort(addr string) (string, string, error) {
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return addr, "", errors.New("no port")
	}
	return addr[:i], addr[i+1:], nil
}
