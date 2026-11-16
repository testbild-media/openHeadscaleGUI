package derp

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestRejectedClients(t *testing.T) {
	allowed := key.NewNode().Public()
	s := &Service{log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		admit: func(k string, _ netip.Addr) bool { return k == allowed.String() }}
	ask := func(k key.NodePublic, src string) bool {
		b, _ := json.Marshal(tailcfg.DERPAdmitClientRequest{NodePublic: k, Source: netip.MustParseAddr(src)})
		rec := httptest.NewRecorder()
		s.handleAdmit(rec, httptest.NewRequest(http.MethodPost, "/admit", bytes.NewReader(b)))
		var resp tailcfg.DERPAdmitClientResponse
		_ = json.NewDecoder(rec.Body).Decode(&resp)
		return resp.Allow
	}
	stale, foreign := key.NewNode().Public(), key.NewNode().Public()
	if !ask(allowed, "198.51.100.1") {
		t.Fatal("known key rejected")
	}
	for i := 0; i < 3; i++ {
		ask(stale, "203.0.113.7")
	}
	ask(foreign, "192.0.2.9")
	got := s.RecentRejected(0)
	if len(got) != 2 || got[0].Key != foreign.String() || got[1].Key != stale.String() || got[1].Count != 3 ||
		got[1].Source.String() != "203.0.113.7" {
		t.Fatalf("unexpected rejection list: %+v", got)
	}
	if s.allowed.Load() != 1 || s.denied.Load() != 4 {
		t.Errorf("stats: allowed %d denied %d", s.allowed.Load(), s.denied.Load())
	}
	for i := 0; i < maxRejected+20; i++ {
		s.recordRejected(key.NewNode().Public().String(), netip.MustParseAddr("192.0.2.1"))
	}
	if n := len(s.RecentRejected(0)); n != maxRejected {
		t.Errorf("list not bounded: %d entries", n)
	}
	if n := len(s.RecentRejected(50)); n != 50 {
		t.Errorf("limit ignored: %d", n)
	}
}
