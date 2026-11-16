package derp

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/net/pktinfo"
	"tailscale.com/net/stun"
)

// stunServer answers STUN binding requests like tailscale's stunserver and
// additionally counts the requests that come from outside the server. If
// devices use the relay but not a single STUN request from outside ever
// arrives, UDP from the internet is blocked (typically by the hoster's
// firewall): the devices then find no direct paths and depend entirely on
// the relay.
type stunServer struct {
	pc      *net.UDPConn
	pktInfo bool
	local   *localAddrs
	log     *slog.Logger

	ext4, ext6, internal atomic.Int64
	last4, last6         atomic.Int64 // unix nanoseconds of the last external request
	since                time.Time
}

func listenSTUN(port string, local *localAddrs, log *slog.Logger) (*stunServer, error) {
	uaddr, err := net.ResolveUDPAddr("udp", port)
	if err != nil {
		return nil, err
	}
	pc, err := net.ListenUDP("udp", uaddr)
	if err != nil {
		return nil, err
	}
	s := &stunServer{pc: pc, local: local, log: log, since: time.Now()}
	if err := pktinfo.Enable(pc); err == nil {
		// answer from the address the request was sent to (multi-homed servers)
		s.pktInfo = true
	} else if !errors.Is(err, errors.ErrUnsupported) {
		log.Debug("STUN: pktinfo unavailable", "err", err)
	}
	return s, nil
}

// serve answers requests until ctx is done.
func (s *stunServer) serve(ctx context.Context) {
	go func() {
		<-ctx.Done()
		s.pc.Close()
	}()
	var buf [64 << 10]byte
	var oob, oobOut [256]byte
	for {
		n, remote, dst, err := s.read(buf[:], oob[:])
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			s.log.Debug("STUN read failed", "err", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		pkt := buf[:n]
		if !stun.Is(pkt) {
			continue
		}
		txid, err := stun.ParseBindingRequest(pkt)
		if err != nil {
			continue
		}
		remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
		s.count(remote.Addr())
		res := stun.Response(txid, remote)
		oo := pktinfo.AppendSrc(oobOut[:0], dst)
		if len(oo) == 0 {
			_, _ = s.pc.WriteToUDPAddrPort(res, remote)
		} else {
			_, _, _ = s.pc.WriteMsgUDPAddrPort(res, oo, remote)
		}
	}
}

func (s *stunServer) read(buf, oob []byte) (int, netip.AddrPort, netip.Addr, error) {
	if !s.pktInfo {
		n, remote, err := s.pc.ReadFromUDPAddrPort(buf)
		return n, remote, netip.Addr{}, err
	}
	n, oobn, _, remote, err := s.pc.ReadMsgUDPAddrPort(buf, oob)
	if err != nil {
		return 0, remote, netip.Addr{}, err
	}
	return n, remote, pktinfo.Dst(oob[:oobn]), nil
}

func (s *stunServer) count(src netip.Addr) {
	switch {
	case s.local.contains(src):
		// the server's own nodes (gateways) ask from the server's addresses
		s.internal.Add(1)
	case src.Is4():
		s.ext4.Add(1)
		s.last4.Store(time.Now().UnixNano())
	default:
		s.ext6.Add(1)
		s.last6.Store(time.Now().UnixNano())
	}
}

func unixNano(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.Unix(0, v)
}

// localAddrs knows the addresses of the server's own interfaces.
type localAddrs struct {
	mu      sync.Mutex
	addrs   map[netip.Addr]bool
	updated time.Time
	// list returns the interface addresses (replaceable in tests)
	list func() []netip.Addr
}

func newLocalAddrs() *localAddrs {
	return &localAddrs{list: interfaceAddrs}
}

func interfaceAddrs() []netip.Addr {
	var out []netip.Addr
	ifs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, a := range ifs {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p.Addr().Unmap())
		}
	}
	return out
}

// contains reports whether addr belongs to this server (loopback or an
// address of one of its interfaces). The list is refreshed every minute.
func (l *localAddrs) contains(addr netip.Addr) bool {
	addr = addr.Unmap()
	if addr.IsLoopback() {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.addrs == nil || time.Since(l.updated) > time.Minute {
		m := map[netip.Addr]bool{}
		for _, a := range l.list() {
			m[a] = true
		}
		l.addrs, l.updated = m, time.Now()
	}
	return l.addrs[addr]
}
