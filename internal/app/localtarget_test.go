package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/testbild-media/openHeadscaleGUI/internal/config"
	"github.com/testbild-media/openHeadscaleGUI/internal/forward"
	"github.com/testbild-media/openHeadscaleGUI/internal/store"
)

func testApp(t *testing.T) (*App, *store.Instance) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "ohg.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ctx := context.Background()
	owner := &store.User{Username: "owner", PasswordHash: "x", Role: store.RoleUser}
	if err := db.CreateUser(ctx, owner); err != nil {
		t.Fatal(err)
	}
	inst := &store.Instance{Slug: "a", Name: "A", OwnerID: owner.ID, Domain: "vpn.example.com", Enabled: true, InternalPort: 42000,
		GatewayPort: 41641, PrefixV4: "100.64.0.0/10", PrefixV6: "fd7a:115c:a1e0::/48", IPAllocation: "sequential",
		BaseDomain: "a.internal", NodeExpiry: "0", EphemeralTimeout: "30m"}
	if err := db.CreateInstance(ctx, inst); err != nil {
		t.Fatal(err)
	}
	return &App{DB: db, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		FwdReg: forward.NewRegistry(), BridgeReg: forward.NewRegistry(), RedirectReg: forward.NewRegistry(),
		Cfg: &config.Config{AdminDomain: "admin.example.com", HTTPAddr: "127.0.0.1:8480", HTTPSAddr: ":443"}}, inst
}

func TestLocalTarget(t *testing.T) {
	a, _ := testApp(t)
	orig := localAddrs
	localAddrs = func() []netip.Addr {
		return []netip.Addr{netip.MustParseAddr("172.17.0.1"), netip.MustParseAddr("192.168.1.5")}
	}
	defer func() { localAddrs = orig }()
	ctx := context.Background()
	for _, c := range []struct {
		host  string
		port  int
		proto string
		want  string // "" = error
	}{
		{"localhost", 9000, "tcp", "127.0.0.1"},
		{"127.0.0.1", 9000, "tcp", "127.0.0.1"},
		{"[::1]", 9000, "tcp", "::1"},
		{"172.17.0.2", 80, "tcp", "172.17.0.2"},      // docker container
		{"192.168.1.20", 443, "tcp", "192.168.1.20"}, // other LAN host: ohg's ports do not matter there
		{"127.0.0.1", 8480, "tcp", ""},               // ohg's own listener
		{"127.0.0.1", 443, "tcp", ""},
		{"172.17.0.1", 443, "tcp", ""}, // server's own docker bridge address
		{"192.168.1.5", 8480, "tcp", ""},
		{"127.0.0.1", 42000, "tcp", ""}, // headscale of an instance
		{"127.0.0.1", 41641, "udp", ""}, // gateway WireGuard
		{"127.0.0.1", 41641, "tcp", "127.0.0.1"},
		{"169.254.169.254", 80, "tcp", ""}, // cloud metadata
		{"100.64.0.5", 80, "tcp", ""},      // tailnet
		{"fd7a:115c:a1e0::5", 80, "tcp", ""},
		{"8.8.8.8", 53, "udp", ""}, // public address
		{"0.0.0.0", 80, "tcp", ""},
		{"nas.local", 80, "tcp", ""}, // names are not resolved
	} {
		got, err := a.localTarget(ctx, c.host, c.port, c.proto)
		if c.want == "" {
			if err == nil {
				t.Errorf("%s:%d/%s allowed (%s), want error", c.host, c.port, c.proto, got)
			}
			continue
		}
		if err != nil || got.String() != c.want {
			t.Errorf("%s:%d/%s: %v %v, want %s", c.host, c.port, c.proto, got, err, c.want)
		}
	}
}

func TestValidateForwardLocalAndRedirect(t *testing.T) {
	a, inst := testApp(t)
	ctx := context.Background()
	owner, _ := a.DB.GetUser(ctx, inst.OwnerID)
	super := &store.User{ID: 99, Username: "root", Role: store.RoleSuperadmin}
	userActor, superActor := Actor{User: owner}, Actor{User: super}

	// a service on the server itself is a server forward, never one of an instance
	local := ForwardRequest{Kind: store.ForwardHTTP, Domain: "os.example.com", Local: true, TargetHost: "127.0.0.1", TargetPort: 9000, Enabled: true}
	for _, actor := range []Actor{userActor, superActor} {
		r := local
		if err := a.validateForward(ctx, actor, inst, &r, nil); err == nil || !strings.Contains(err.Error(), "Server-Freigaben") {
			t.Errorf("%s: local target inside an instance: %v", actor.User.Username, err)
		}
	}
	r := local
	r.Local = false // the scope decides, not the form
	if err := a.validateForward(ctx, superActor, nil, &r, nil); err != nil || !r.Local || r.TargetHost != "127.0.0.1" || r.NodeID != 0 {
		t.Errorf("server forward: %v %+v", err, r)
	}
	r = local
	if err := a.validateForward(ctx, userActor, nil, &r, nil); err != ErrForbidden {
		t.Errorf("normal user creates a server forward: %v", err)
	}
	f := &store.Forward{LocalTarget: true} // server forward
	if a.canManageForward(userActor, nil, f) || !a.canManageForward(superActor, nil, f) || a.canManageForward(superActor, inst, f) {
		t.Error("server forwards: superadmins only, and only in the server scope")
	}

	r = ForwardRequest{Kind: store.ForwardRedirect, Domain: "web.example.com"}
	if err := a.validateForward(ctx, superActor, inst, &r, nil); err == nil {
		t.Error("redirects must not be created as forwards any more")
	}
}

// Server forwards work without an instance: they keep working while the
// only instance is disabled and survive its deletion.
func TestServerForwards(t *testing.T) {
	a, inst := testApp(t)
	ctx := context.Background()
	a.Cfg.DataDir = t.TempDir()
	a.Fwd = forward.NewManager(func(context.Context, int64, string, string) (net.Conn, error) {
		return nil, errors.New("server forwards must not dial through a tailnet")
	}, a.FwdReg, a.Log, "127.0.0.1")
	t.Cleanup(func() { a.Fwd.Sync(nil) })
	owner, _ := a.DB.GetUser(ctx, inst.OwnerID)
	super, user := Actor{User: &store.User{ID: 99, Username: "root", Role: store.RoleSuperadmin}}, Actor{User: owner}

	// targets on the server: a TCP echo and a web server
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "hello from "+r.Host) }))
	defer web.Close()
	webPort := web.Listener.Addr().(*net.TCPAddr).Port
	probe, _ := net.Listen("tcp", "127.0.0.1:0")
	pub := probe.Addr().(*net.TCPAddr).Port
	probe.Close()

	if _, err := a.CreateForward(ctx, user, nil, ForwardRequest{Kind: store.ForwardTCP, PublicPort: pub, TargetHost: "127.0.0.1",
		TargetPort: echo.Addr().(*net.TCPAddr).Port, Enabled: true}); err != ErrForbidden {
		t.Fatalf("normal user creates a server forward: %v", err)
	}
	tcp, err := a.CreateForward(ctx, super, nil, ForwardRequest{Kind: store.ForwardTCP, PublicPort: pub, TargetHost: "127.0.0.1",
		TargetPort: echo.Addr().(*net.TCPAddr).Port, Enabled: true})
	if err != nil || tcp.InstanceID != 0 || !tcp.LocalTarget {
		t.Fatalf("server TCP forward: %+v %v", tcp, err)
	}
	if _, err := a.CreateForward(ctx, super, nil, ForwardRequest{Kind: store.ForwardHTTP, Domain: "os.example.com",
		TargetHost: "localhost", TargetPort: webPort, PreserveHost: true, Enabled: true}); err != nil {
		t.Fatalf("server HTTPS forward: %v", err)
	}
	if l, _ := a.DB.ListForwards(ctx, store.ServerForwards); len(l) != 2 {
		t.Errorf("want 2 server forwards, got %d", len(l))
	}
	if l, _ := a.DB.ListForwards(ctx, inst.ID); len(l) != 0 {
		t.Errorf("server forwards listed in the instance: %d", len(l))
	}

	inst.Enabled = false
	if err := a.DB.UpdateInstance(ctx, inst); err != nil {
		t.Fatal(err)
	}
	a.afterForwardChange(ctx)
	check := func(when string) {
		t.Helper()
		if e := a.Fwd.ListenError("tcp", pub); e != "" {
			t.Fatalf("%s: listener: %s", when, e)
		}
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(pub)), 2*time.Second)
		if err != nil {
			t.Fatalf("%s: TCP forward not listening: %v", when, err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 4)
		if _, err := c.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
			t.Fatalf("%s: TCP forward: %q %v", when, buf, err)
		}
		h := a.Route("os.example.com")
		if h == nil {
			t.Fatalf("%s: no route for the HTTPS forward", when)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "https://os.example.com/", nil))
		if rec.Code != http.StatusOK || rec.Body.String() != "hello from os.example.com" {
			t.Fatalf("%s: HTTPS forward: %d %q", when, rec.Code, rec.Body.String())
		}
	}
	check("instance disabled")

	if err := a.DB.DeleteInstance(ctx, inst.ID); err != nil {
		t.Fatal(err)
	}
	a.afterForwardChange(ctx)
	if l, _ := a.DB.ListForwards(ctx, store.ServerForwards); len(l) != 2 {
		t.Fatalf("server forwards deleted with the instance: %d left", len(l))
	}
	check("instance deleted")

	// stored with NULL instance: the database refuses a local target inside
	// an instance and a server forward without local target
	if err := a.DB.CreateForward(ctx, &store.Forward{Kind: store.ForwardTCP, PublicPort: 20001, TargetHost: "127.0.0.1", TargetPort: 1}); err == nil {
		t.Error("server forward without local target stored")
	}
}

func TestSiteNameSetting(t *testing.T) {
	a, _ := testApp(t)
	ctx := context.Background()
	super := Actor{User: &store.User{ID: 99, Role: store.RoleSuperadmin}}
	if a.SiteName(ctx) != DefaultSiteName {
		t.Fatal("default name missing")
	}
	s := a.Settings(ctx)
	s.SiteName = "  Walzwerk \t VPN  "
	if err := a.SaveSettings(ctx, super, s); err != nil {
		t.Fatal(err)
	}
	if got := a.SiteName(ctx); got != "Walzwerk VPN" {
		t.Errorf("name not normalised: %q", got)
	}
	s.SiteName = strings.Repeat("x", 41)
	if err := a.SaveSettings(ctx, super, s); err == nil {
		t.Error("overlong name accepted")
	}
	s.SiteName = ""
	_ = a.SaveSettings(ctx, super, s)
	if a.SiteName(ctx) != DefaultSiteName {
		t.Error("empty name does not restore the default")
	}
}
