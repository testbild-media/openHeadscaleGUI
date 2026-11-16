package edge

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/testbild-media/openHeadscaleGUI/internal/forward"
)

func TestRedirectHandler(t *testing.T) {
	c := &forward.Counters{}
	for _, tc := range []struct {
		url      string
		keep     bool
		code     int
		req      string
		wantCode int
		wantLoc  string
	}{
		{"https://www.google.com", false, 302, "/x/y?q=1", 302, "https://www.google.com"},
		{"https://www.google.com", true, 301, "/search?q=ohg", 301, "https://www.google.com/search?q=ohg"},
		{"https://www.google.com/", true, 308, "/", 308, "https://www.google.com/"},
		{"https://example.org/base/?a=1", true, 307, "/sub?b=2", 307, "https://example.org/base/sub?a=1&b=2"},
		{"https://example.org", true, 999, "/p", 302, "https://example.org/p"}, // invalid code -> 302
	} {
		h := RedirectHandler(RedirectTarget{URL: tc.url, KeepPath: tc.keep, Code: tc.code, C: c})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://web.example.com"+tc.req, nil))
		if rec.Code != tc.wantCode || rec.Header().Get("Location") != tc.wantLoc {
			t.Errorf("%s keep=%v %s: %d %q, want %d %q", tc.url, tc.keep, tc.req, rec.Code, rec.Header().Get("Location"), tc.wantCode, tc.wantLoc)
		}
	}
	if c.Total.Load() != 5 {
		t.Errorf("hits counted: %d", c.Total.Load())
	}
	h := RedirectHandler(RedirectTarget{URL: "https://example.org", Code: 302, Allow: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}})
	req := httptest.NewRequest(http.MethodGet, "https://web.example.com/", nil)
	req.RemoteAddr = "203.0.113.1:1"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("allowlist not applied: %d", rec.Code)
	}
}
