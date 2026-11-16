package derp

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/net/stun"
)

func TestSTUNCountsExternalRequests(t *testing.T) {
	own := netip.MustParseAddr("85.215.175.236")
	la := &localAddrs{list: func() []netip.Addr { return []netip.Addr{own} }}
	s := &stunServer{local: la}
	for _, a := range []string{"127.0.0.1", "::1", "85.215.175.236", "::ffff:85.215.175.236"} {
		s.count(netip.MustParseAddr(a))
	}
	if s.internal.Load() != 4 || s.ext4.Load() != 0 || s.ext6.Load() != 0 {
		t.Fatalf("own addresses counted as external: int=%d v4=%d v6=%d", s.internal.Load(), s.ext4.Load(), s.ext6.Load())
	}
	s.count(netip.MustParseAddr("88.130.68.254"))
	s.count(netip.MustParseAddr("2003:ce:736:1900::1550"))
	s.count(netip.MustParseAddr("2003:ce:736:1900::1551"))
	if s.ext4.Load() != 1 || s.ext6.Load() != 2 {
		t.Fatalf("external requests: v4=%d v6=%d", s.ext4.Load(), s.ext6.Load())
	}
	if unixNano(s.last4.Load()).IsZero() || unixNano(s.last6.Load()).IsZero() {
		t.Error("time of the last external request not recorded")
	}
}

func TestSTUNAnswersBindingRequests(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	s, err := listenSTUN("127.0.0.1:0", newLocalAddrs(), log)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.serve(ctx)

	c, err := net.DialUDP("udp", nil, s.pc.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	tx := stun.NewTxID()
	if _, err := c.Write(stun.Request(tx)); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	gotTx, addr, err := stun.ParseResponse(buf[:n])
	if err != nil || gotTx != tx {
		t.Fatalf("bad response: %v", err)
	}
	if want := c.LocalAddr().(*net.UDPAddr).AddrPort(); addr.Port() != want.Port() || !addr.Addr().IsLoopback() {
		t.Errorf("mapped address %v, want %v", addr, want)
	}
	if s.internal.Load() != 1 || s.ext4.Load() != 0 {
		t.Errorf("loopback request: internal=%d ext4=%d", s.internal.Load(), s.ext4.Load())
	}
	// not STUN: ignored, no answer, no count
	_, _ = c.Write([]byte("hello"))
	_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := c.Read(buf); err == nil {
		t.Error("answered a non-STUN packet")
	}
	if s.internal.Load() != 1 {
		t.Error("non-STUN packet counted")
	}
}
