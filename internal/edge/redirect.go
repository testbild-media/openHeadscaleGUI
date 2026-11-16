package edge

import (
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/testbild-media/openHeadscaleGUI/internal/forward"
)

// RedirectTarget configures a plain HTTP redirect of a domain.
type RedirectTarget struct {
	URL      string // absolute http(s) URL
	Code     int    // 301, 302, 307 or 308
	KeepPath bool   // append the request path and query
	Allow    []netip.Prefix
	C        *forward.Counters
}

// ValidRedirectCode reports whether code is a supported redirect status.
func ValidRedirectCode(code int) bool {
	switch code {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

// RedirectLocation builds the Location for a request: the target URL, with
// the request path and query appended when keepPath is set.
func RedirectLocation(target string, keepPath bool, r *http.Request) string {
	if !keepPath {
		return target
	}
	u, err := url.Parse(target)
	if err != nil {
		return target
	}
	if p := r.URL.EscapedPath(); p != "" && p != "/" {
		u.RawPath = ""
		u.Path = strings.TrimSuffix(u.Path, "/") + r.URL.Path
	}
	if r.URL.RawQuery != "" {
		if u.RawQuery != "" {
			u.RawQuery += "&" + r.URL.RawQuery
		} else {
			u.RawQuery = r.URL.RawQuery
		}
	}
	return u.String()
}

// RedirectHandler answers every request of the domain with a redirect.
func RedirectHandler(rt RedirectTarget) http.Handler {
	code := rt.Code
	if !ValidRedirectCode(code) {
		code = http.StatusFound
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !forward.Allowed(rt.Allow, ClientIP(r)) {
			writeError(w, http.StatusForbidden, "Zugriff von dieser Adresse nicht erlaubt.")
			return
		}
		if rt.C != nil {
			rt.C.Total.Add(1)
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		http.Redirect(w, r, RedirectLocation(rt.URL, rt.KeepPath, r), code)
	})
}
