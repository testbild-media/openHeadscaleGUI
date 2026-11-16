package app

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/testbild-media/openHeadscaleGUI/internal/edge"
	"github.com/testbild-media/openHeadscaleGUI/internal/store"
)

// Redirects answer every request of a domain with an HTTP redirect – e.g.
// alt.example.com → https://neu.example.com or → https://www.example.org.
// They do not belong to an instance; normal users may only use domains
// below the allowed suffixes and only manage their own redirects.

// RedirectRequest is the editable part of a redirect.
type RedirectRequest struct {
	Domain      string
	URL         string
	Code        int
	KeepPath    bool
	AllowCIDRs  string
	Enabled     bool
	Description string
}

// RedirectRequestFrom converts a redirect into editable values.
func RedirectRequestFrom(r *store.Redirect) RedirectRequest {
	return RedirectRequest{Domain: r.Domain, URL: r.URL, Code: r.Code, KeepPath: r.KeepPath, AllowCIDRs: r.AllowCIDRs,
		Enabled: r.Enabled, Description: r.Description}
}

// CanManageRedirect: superadmins manage all redirects, users their own.
func CanManageRedirect(u *store.User, r *store.Redirect) bool {
	return u != nil && !u.Disabled && (u.IsSuperadmin() || r.OwnerID == u.ID)
}

func (a *App) validateRedirect(ctx context.Context, actor Actor, r *RedirectRequest, existing *store.Redirect) error {
	if actor.User == nil {
		return ErrForbidden
	}
	var exceptID int64
	if existing != nil {
		exceptID = existing.ID
	}
	r.Domain = NormalizeDomain(r.Domain)
	if existing == nil || existing.Domain != r.Domain {
		if err := a.checkDomainAllowed(ctx, actor, r.Domain); err != nil {
			return err
		}
	}
	if used := a.domainClaimed(ctx, r.Domain, 0, 0, exceptID); used != "" {
		return Errf("Die Domain %s wird bereits verwendet (%s)", r.Domain, used)
	}
	target := strings.TrimSpace(r.URL)
	if target != "" && !strings.Contains(target, "://") {
		target = "https://" + target // "neu.example.com" means https://neu.example.com
	}
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || len(target) > 2048 {
		return Errf("Bitte eine Ziel-Adresse angeben, z. B. https://neu.example.com oder https://www.example.org/seite")
	}
	if NormalizeDomain(u.Hostname()) == r.Domain && (u.Path == "" || u.Path == "/") {
		return Errf("Die Weiterleitung würde auf sich selbst zeigen")
	}
	r.URL = u.String()
	if r.Code == 0 {
		r.Code = http.StatusFound
	}
	if !edge.ValidRedirectCode(r.Code) {
		return Errf("Ungültige Art der Weiterleitung (erlaubt: 301, 302, 307, 308)")
	}
	if r.AllowCIDRs, err = ParseCIDRs(r.AllowCIDRs); err != nil {
		return err
	}
	r.Description = strings.TrimSpace(r.Description)
	if len([]rune(r.Description)) > 200 {
		return Errf("Beschreibung: höchstens 200 Zeichen")
	}
	return nil
}

func fillRedirect(d *store.Redirect, r RedirectRequest) {
	d.Domain, d.URL, d.Code, d.KeepPath, d.AllowCIDRs = r.Domain, r.URL, r.Code, r.KeepPath, r.AllowCIDRs
	d.Enabled, d.Description = r.Enabled, r.Description
}

func describeRedirect(r *store.Redirect) string {
	return fmt.Sprintf("%s → %s (%d)", r.Domain, r.URL, r.Code)
}

// Redirects returns the redirects the actor may see.
func (a *App) Redirects(ctx context.Context, actor Actor) ([]*store.Redirect, error) {
	if actor.User == nil {
		return nil, ErrForbidden
	}
	if actor.User.IsSuperadmin() {
		return a.DB.ListRedirects(ctx, 0)
	}
	return a.DB.ListRedirects(ctx, actor.User.ID)
}

// CreateRedirect adds a redirect owned by the actor.
func (a *App) CreateRedirect(ctx context.Context, actor Actor, r RedirectRequest) (*store.Redirect, error) {
	if err := a.validateRedirect(ctx, actor, &r, nil); err != nil {
		return nil, err
	}
	d := &store.Redirect{OwnerID: actor.User.ID}
	fillRedirect(d, r)
	if err := a.DB.CreateRedirect(ctx, d); err != nil {
		return nil, err
	}
	_ = a.RebuildRoutes(ctx)
	a.Audit(ctx, actor, 0, "redirect.create", describeRedirect(d))
	return d, nil
}

// UpdateRedirect changes a redirect.
func (a *App) UpdateRedirect(ctx context.Context, actor Actor, d *store.Redirect, r RedirectRequest) error {
	if !CanManageRedirect(actor.User, d) {
		return ErrForbidden
	}
	if err := a.validateRedirect(ctx, actor, &r, d); err != nil {
		return err
	}
	fillRedirect(d, r)
	if err := a.DB.UpdateRedirect(ctx, d); err != nil {
		return err
	}
	_ = a.RebuildRoutes(ctx)
	a.Audit(ctx, actor, 0, "redirect.update", describeRedirect(d))
	return nil
}

// SetRedirectEnabled toggles a redirect.
func (a *App) SetRedirectEnabled(ctx context.Context, actor Actor, d *store.Redirect, on bool) error {
	if !CanManageRedirect(actor.User, d) {
		return ErrForbidden
	}
	d.Enabled = on
	if err := a.DB.UpdateRedirect(ctx, d); err != nil {
		return err
	}
	_ = a.RebuildRoutes(ctx)
	a.Audit(ctx, actor, 0, map[bool]string{true: "redirect.enable", false: "redirect.disable"}[on], describeRedirect(d))
	return nil
}

// DeleteRedirect removes a redirect.
func (a *App) DeleteRedirect(ctx context.Context, actor Actor, d *store.Redirect) error {
	if !CanManageRedirect(actor.User, d) {
		return ErrForbidden
	}
	if err := a.DB.DeleteRedirect(ctx, d.ID); err != nil {
		return err
	}
	_ = a.RebuildRoutes(ctx)
	a.Audit(ctx, actor, 0, "redirect.delete", describeRedirect(d))
	return nil
}
