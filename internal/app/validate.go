package app

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// UserError is an error whose message is safe to show to the user.
type UserError struct{ Msg string }

func (e *UserError) Error() string { return e.Msg }

// Errf creates a UserError.
func Errf(format string, args ...any) error { return &UserError{Msg: fmt.Sprintf(format, args...)} }

// IsUserError reports whether err is a UserError.
func IsUserError(err error) bool {
	var ue *UserError
	return errors.As(err, &ue)
}

var (
	labelRe    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	slugRe     = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}[a-z0-9]$`)
	hsUserRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	usernameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{2,31}$`)
	authIDRe   = regexp.MustCompile(`hskey-authreq-[A-Za-z0-9_-]{24}`)
	tagRe      = regexp.MustCompile(`^tag:[a-z0-9][a-z0-9-]{0,62}$`)
)

// ValidDomain validates a DNS host name (lowercase, at least two labels).
func ValidDomain(d string) error {
	d = strings.ToLower(strings.TrimSpace(d))
	if len(d) == 0 || len(d) > 253 {
		return Errf("Ungültige Domain")
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return Errf("Die Domain muss mindestens zwei Teile haben (z. B. vpn.example.com)")
	}
	for _, l := range labels {
		if !labelRe.MatchString(l) {
			return Errf("Ungültige Domain %q", d)
		}
	}
	if _, err := netip.ParseAddr(d); err == nil {
		return Errf("Bitte einen Domainnamen statt einer IP-Adresse verwenden")
	}
	tld := labels[len(labels)-1]
	if _, err := strconv.Atoi(tld); err == nil {
		return Errf("Ungültige Top-Level-Domain")
	}
	return nil
}

// NormalizeDomain lowercases and trims a domain.
func NormalizeDomain(d string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
}

// ValidSlug validates an instance slug.
func ValidSlug(s string) error {
	if !slugRe.MatchString(s) {
		return Errf("Kurzname: 3–32 Zeichen, Kleinbuchstaben, Ziffern und Bindestrich, beginnt mit einem Buchstaben")
	}
	return nil
}

// ValidHSUser validates a headscale user name.
func ValidHSUser(s string) error {
	if !hsUserRe.MatchString(s) {
		return Errf("Tailnet-Benutzer: 1–63 Zeichen, Kleinbuchstaben, Ziffern, Punkt, Unterstrich, Bindestrich")
	}
	return nil
}

// ValidUsername validates a GUI user name.
func ValidUsername(s string) error {
	if !usernameRe.MatchString(s) {
		return Errf("Benutzername: 3–32 Zeichen, Buchstaben, Ziffern, Punkt, Unterstrich, Bindestrich")
	}
	return nil
}

// NodeName converts a free text name into a valid DNS label.
func NodeName(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	dash := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		case r == '-' || r == ' ' || r == '_' || r == '.':
			if !dash && b.Len() > 0 {
				b.WriteByte('-')
				dash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 63 {
		out = strings.Trim(out[:63], "-")
	}
	if out == "" || !labelRe.MatchString(out) {
		return "", Errf("Ungültiger Gerätename")
	}
	return out, nil
}

// ParseAuthID extracts a headscale auth ID from free text (URL, command, ID).
func ParseAuthID(s string) (string, bool) {
	m := authIDRe.FindString(s)
	return m, m != ""
}

// ValidAuthID reports whether s is exactly a headscale auth ID.
func ValidAuthID(s string) bool {
	return len(s) == 38 && authIDRe.MatchString(s)
}

// ValidTag validates an ACL tag.
func ValidTag(t string) error {
	if !tagRe.MatchString(t) {
		return Errf("Ungültiger Tag %q (Format: tag:name)", t)
	}
	return nil
}

// SplitList splits a comma/space/newline separated list.
func SplitList(s string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == ';' || r == '\t' }) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ParseRoutes validates a list of CIDR routes.
func ParseRoutes(s string) ([]string, error) {
	var out []string
	for _, p := range SplitList(s) {
		pr, err := netip.ParsePrefix(p)
		if err != nil {
			return nil, Errf("Ungültiges Netz %q", p)
		}
		out = append(out, pr.Masked().String())
	}
	return out, nil
}

// ParseCIDRs validates an allow list (CIDRs or single IPs) and returns a
// normalized string.
func ParseCIDRs(s string) (string, error) {
	var out []string
	for _, p := range SplitList(s) {
		if strings.Contains(p, "/") {
			pr, err := netip.ParsePrefix(p)
			if err != nil {
				return "", Errf("Ungültiges Netz %q", p)
			}
			out = append(out, pr.Masked().String())
			continue
		}
		a, err := netip.ParseAddr(p)
		if err != nil {
			return "", Errf("Ungültige IP %q", p)
		}
		out = append(out, a.Unmap().String())
	}
	return strings.Join(out, ","), nil
}

var (
	cgnat         = netip.MustParsePrefix("100.64.0.0/10")
	tsULA         = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	quad100       = netip.MustParseAddr("100.100.100.100")
	chromeOSRange = netip.MustParsePrefix("100.115.92.0/23")
)

// ValidPrefixV4 validates a tailnet IPv4 prefix.
func ValidPrefixV4(s string) (string, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil || !p.Addr().Is4() {
		return "", Errf("Ungültiges IPv4-Präfix")
	}
	p = p.Masked()
	if !cgnat.Contains(p.Addr()) || p.Bits() < 10 || p.Bits() > 28 {
		return "", Errf("Das IPv4-Präfix muss innerhalb von 100.64.0.0/10 liegen (/10 bis /28)")
	}
	return p.String(), nil
}

// ValidPrefixV6 validates a tailnet IPv6 prefix.
func ValidPrefixV6(s string) (string, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil || !p.Addr().Is6() {
		return "", Errf("Ungültiges IPv6-Präfix")
	}
	p = p.Masked()
	if !tsULA.Contains(p.Addr()) || p.Bits() < 48 || p.Bits() > 120 {
		return "", Errf("Das IPv6-Präfix muss innerhalb von fd7a:115c:a1e0::/48 liegen")
	}
	return p.String(), nil
}

// ValidDuration validates a headscale duration ("0" allowed).
func ValidDuration(s string, allowZero bool) error {
	if allowZero && (s == "0" || s == "") {
		return nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < time.Minute || d > 10*365*24*time.Hour {
		return Errf("Ungültige Dauer %q (z. B. 30m, 24h, 2160h)", s)
	}
	return nil
}

// ValidNameserver validates a DNS server address.
func ValidNameserver(s string) error {
	if _, err := netip.ParseAddr(s); err == nil {
		return nil
	}
	if strings.HasPrefix(s, "https://") && len(s) < 200 {
		return nil
	}
	return Errf("Ungültiger DNS-Server %q (IP-Adresse oder DoH-URL)", s)
}

// ValidTargetHost validates a forward target (IP or DNS name).
func ValidTargetHost(s string) error {
	if a, err := netip.ParseAddr(s); err == nil {
		if a.IsUnspecified() || a.IsMulticast() {
			return Errf("Ungültige Ziel-IP")
		}
		return nil
	}
	if len(s) > 253 {
		return Errf("Ungültiges Ziel")
	}
	for _, l := range strings.Split(strings.ToLower(s), ".") {
		if !labelRe.MatchString(l) {
			return Errf("Ungültiges Ziel %q", s)
		}
	}
	return nil
}

// ValidPort validates a TCP/UDP port.
func ValidPort(p int) error {
	if p < 1 || p > 65535 {
		return Errf("Ungültiger Port %d", p)
	}
	return nil
}
