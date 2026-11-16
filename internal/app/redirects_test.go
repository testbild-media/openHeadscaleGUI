package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/testbild-media/openHeadscaleGUI/internal/store"
)

func TestRedirects(t *testing.T) {
	a, inst := testApp(t) // admin domain admin.example.com, instance domain vpn.example.com
	ctx := context.Background()
	owner, _ := a.DB.GetUser(ctx, inst.OwnerID)
	other := &store.User{Username: "bert", PasswordHash: "x", Role: store.RoleUser}
	root := &store.User{Username: "root", PasswordHash: "x", Role: store.RoleSuperadmin}
	for _, u := range []*store.User{other, root} {
		if err := a.DB.CreateUser(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	super, user, stranger := Actor{User: root}, Actor{User: owner}, Actor{User: other}

	// subdomain to another subdomain, short form without scheme
	r, err := a.CreateRedirect(ctx, super, RedirectRequest{Domain: "Alt.Example.com", URL: "neu.example.com", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if r.Domain != "alt.example.com" || r.URL != "https://neu.example.com" || r.Code != 302 || r.OwnerID != root.ID {
		t.Errorf("not normalised: %+v", r)
	}
	// subdomain to a completely different domain, permanent, with path
	r2, err := a.CreateRedirect(ctx, user, RedirectRequest{Domain: "shop.example.com", URL: "https://www.example.org/shop",
		Code: 301, KeepPath: true, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if h := (*a.routes.Load())["shop.example.com"]; h == nil {
		t.Error("redirect not routed")
	}
	for name, bad := range map[string]RedirectRequest{
		"own domain":         {Domain: "loop.example.com", URL: "https://loop.example.com/"},
		"admin domain":       {Domain: "admin.example.com", URL: "https://x.org"},
		"instance domain":    {Domain: "vpn.example.com", URL: "https://x.org"},
		"taken by redirect":  {Domain: "alt.example.com", URL: "https://x.org"},
		"javascript":         {Domain: "x.example.com", URL: "javascript:alert(1)"},
		"credentials in URL": {Domain: "x.example.com", URL: "https://user:pw@x.org"},
		"bad code":           {Domain: "x.example.com", URL: "https://x.org", Code: 200},
		"bad domain":         {Domain: "not a domain", URL: "https://x.org"},
	} {
		if _, err := a.CreateRedirect(ctx, super, bad); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// the redirect domain is taken for forwards and instances too
	fw := ForwardRequest{Kind: store.ForwardHTTP, Domain: "alt.example.com", NodeID: 0, TargetHost: "100.64.0.9", TargetPort: 80}
	if err := a.validateForward(ctx, super, inst, &fw, nil); err == nil {
		t.Error("forward on a redirect domain accepted")
	}
	// permissions: own redirects only, superadmins all
	if list, _ := a.Redirects(ctx, user); len(list) != 1 || list[0].ID != r2.ID {
		t.Errorf("user sees %d redirects", len(list))
	}
	if list, _ := a.Redirects(ctx, super); len(list) != 2 {
		t.Errorf("superadmin sees %d redirects", len(list))
	}
	if err := a.DeleteRedirect(ctx, stranger, r2); err != ErrForbidden {
		t.Errorf("stranger deleted a redirect: %v", err)
	}
	if err := a.UpdateRedirect(ctx, super, r2, RedirectRequest{Domain: "shop.example.com", URL: "https://www.example.net", Code: 308, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if got, _ := a.DB.GetRedirect(ctx, r2.ID); got.URL != "https://www.example.net" || got.Code != 308 || got.OwnerID != owner.ID {
		t.Errorf("update: %+v", got)
	}
	if err := a.SetRedirectEnabled(ctx, user, r2, false); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	(*a.routes.Load())["shop.example.com"].ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://shop.example.com/", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("disabled redirect still active: %d", rec.Code)
	}
}
