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

// redirectHandler answers every request of a domain with a redirect. The
// edge recognises it to redirect plain HTTP requests in one step (instead
// of http -> https of the same domain -> target).
type redirectHandler struct {
	rt   RedirectTarget
	code int
}

// RedirectHandler answers every request of the domain with a redirect.
func RedirectHandler(rt RedirectTarget) http.Handler {
	code := rt.Code
	if !ValidRedirectCode(code) {
		code = http.StatusFound
	}
	return &redirectHandler{rt: rt, code: code}
}

func (h *redirectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !forward.Allowed(h.rt.Allow, ClientIP(r)) {
		writeError(w, http.StatusForbidden, "Zugriff von dieser Adresse nicht erlaubt.")
		return
	}
	if h.rt.C != nil {
		h.rt.C.Total.Add(1)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, RedirectLocation(h.rt.URL, h.rt.KeepPath, r), h.code)
}
