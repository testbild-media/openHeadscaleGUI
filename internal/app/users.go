package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/testbild-media/openHeadscaleGUI/internal/secure"
	"github.com/testbild-media/openHeadscaleGUI/internal/store"
)

// UserRequest describes a GUI account change.
type UserRequest struct {
	Username     string
	Email        string
	Password     string
	Role         string
	Disabled     bool
	MaxInstances int
	MustChange   bool
}

func validEmail(e string) bool {
	if e == "" {
		return true
	}
	at := strings.LastIndex(e, "@")
	return at > 0 && at < len(e)-3 && len(e) <= 254 && !strings.ContainsAny(e, " <>\r\n")
}

// CreateUser creates a GUI account (superadmin only, or bootstrap when
// actor.User is nil and no users exist).
func (a *App) CreateUser(ctx context.Context, actor Actor, r UserRequest) (*store.User, error) {
	if actor.User == nil {
		n, err := a.DB.CountUsers(ctx)
		if err != nil {
			return nil, err
		}
		if n > 0 {
			return nil, ErrForbidden
		}
		r.Role = store.RoleSuperadmin
	} else if !actor.User.IsSuperadmin() {
		return nil, ErrForbidden
	}
	r.Username = strings.TrimSpace(r.Username)
	if err := ValidUsername(r.Username); err != nil {
		return nil, err
	}
	if _, err := a.DB.GetUserByName(ctx, r.Username); err == nil {
		return nil, Errf("Der Benutzername ist bereits vergeben")
	}
	r.Email = strings.TrimSpace(r.Email)
	if !validEmail(r.Email) {
		return nil, Errf("Ungültige E-Mail-Adresse")
	}
	if r.Role != store.RoleSuperadmin && r.Role != store.RoleUser {
		r.Role = store.RoleUser
	}
	if err := secure.CheckPasswordPolicy(r.Password, r.Username); err != nil {
		return nil, &UserError{Msg: err.Error()}
	}
	if r.MaxInstances <= 0 {
		r.MaxInstances = a.Settings(ctx).DefaultMaxInst
	}
	hash, err := secure.HashPassword(ctx, r.Password)
	if err != nil {
		return nil, err
	}
	u := &store.User{
		Username: r.Username, Email: r.Email, PasswordHash: hash, Role: r.Role,
		Disabled: r.Disabled, MaxInstances: r.MaxInstances, MustChangePassword: r.MustChange,
	}
	if err := a.DB.CreateUser(ctx, u); err != nil {
		return nil, err
	}
	a.Audit(ctx, actor, 0, "user.create", fmt.Sprintf("%s (%s)", u.Username, u.Role))
	return u, nil
}

// UpdateUser changes role, mail, quota and state of an account.
func (a *App) UpdateUser(ctx context.Context, actor Actor, u *store.User, r UserRequest) error {
	if !actor.User.IsSuperadmin() {
		return ErrForbidden
	}
	r.Email = strings.TrimSpace(r.Email)
	if !validEmail(r.Email) {
		return Errf("Ungültige E-Mail-Adresse")
	}
	if r.Role != store.RoleSuperadmin && r.Role != store.RoleUser {
		return Errf("Ungültige Rolle")
	}
	if r.MaxInstances < 0 || r.MaxInstances > 1000 {
		return Errf("Ungültige Instanz-Quote")
	}
	if u.IsSuperadmin() && (r.Role != store.RoleSuperadmin || r.Disabled) {
		n, err := a.DB.CountSuperadmins(ctx)
		if err != nil {
			return err
		}
		if n <= 1 && !u.Disabled {
			return Errf("Der letzte aktive Superadmin kann nicht herabgestuft oder deaktiviert werden")
		}
	}
	if u.ID == actor.User.ID && (r.Disabled || r.Role != store.RoleSuperadmin) {
		return Errf("Du kannst dich nicht selbst deaktivieren oder herabstufen")
	}
	u.Email, u.Role, u.Disabled, u.MaxInstances = r.Email, r.Role, r.Disabled, r.MaxInstances
	if err := a.DB.UpdateUserProfile(ctx, u); err != nil {
		return err
	}
	if u.Disabled {
		_ = a.DB.DeleteUserSessions(ctx, u.ID, "")
	}
	a.Audit(ctx, actor, 0, "user.update", fmt.Sprintf("%s role=%s disabled=%v", u.Username, u.Role, u.Disabled))
	return nil
}

// SetUserPassword sets a new password (admin reset or own change).
func (a *App) SetUserPassword(ctx context.Context, actor Actor, u *store.User, password string, mustChange bool, keepSession string) error {
	if !actor.User.IsSuperadmin() && actor.User.ID != u.ID {
		return ErrForbidden
	}
	if err := secure.CheckPasswordPolicy(password, u.Username); err != nil {
		return &UserError{Msg: err.Error()}
	}
	hash, err := secure.HashPassword(ctx, password)
	if err != nil {
		return err
	}
	if err := a.DB.SetPassword(ctx, u.ID, hash, mustChange); err != nil {
		return err
	}
	// invalidate all other sessions of that user
	_ = a.DB.DeleteUserSessions(ctx, u.ID, keepSession)
	a.Audit(ctx, actor, 0, "user.password", u.Username)
	return nil
}

// ResetUser2FA disables 2FA of an account (superadmin).
func (a *App) ResetUser2FA(ctx context.Context, actor Actor, u *store.User) error {
	if !actor.User.IsSuperadmin() {
		return ErrForbidden
	}
	if err := a.DB.SetTOTP(ctx, u.ID, nil, false); err != nil {
		return err
	}
	_ = a.DB.ReplaceRecoveryCodes(ctx, u.ID, nil)
	_ = a.DB.DeleteUserSessions(ctx, u.ID, "")
	a.Audit(ctx, actor, 0, "user.2fa_reset", u.Username)
	return nil
}

// UnlockUser clears a login lock.
func (a *App) UnlockUser(ctx context.Context, actor Actor, u *store.User) error {
	if !actor.User.IsSuperadmin() {
		return ErrForbidden
	}
	if err := a.DB.UnlockUser(ctx, u.ID); err != nil {
		return err
	}
	a.Audit(ctx, actor, 0, "user.unlock", u.Username)
	return nil
}

// DeleteUser removes an account. Its instances must be transferred first.
func (a *App) DeleteUser(ctx context.Context, actor Actor, u *store.User) error {
	if !actor.User.IsSuperadmin() {
		return ErrForbidden
	}
	if u.ID == actor.User.ID {
		return Errf("Du kannst dich nicht selbst löschen")
	}
	n, err := a.DB.CountInstancesByOwner(ctx, u.ID)
	if err != nil {
		return err
	}
	if n > 0 {
		return Errf("Der Benutzer besitzt noch %d Instanz(en) – bitte zuerst übertragen oder löschen", n)
	}
	if u.IsSuperadmin() {
		c, _ := a.DB.CountSuperadmins(ctx)
		if c <= 1 {
			return Errf("Der letzte Superadmin kann nicht gelöscht werden")
		}
	}
	if err := a.DB.DeleteUser(ctx, u.ID); err != nil {
		return err
	}
	a.Audit(ctx, actor, 0, "user.delete", u.Username)
	return nil
}

// ---- 2FA ----

// Begin2FA creates a new (not yet active) TOTP secret.
func (a *App) Begin2FA(ctx context.Context, u *store.User) (secret, uri, qr string, err error) {
	secret = secure.NewTOTPSecret()
	uri = secure.TOTPURI("OpenHeadscaleGUI ("+a.Cfg.AdminDomain+")", u.Username, secret)
	qr, err = secure.QRDataURI(uri)
	if err != nil {
		return "", "", "", err
	}
	if err := a.DB.SetTOTP(ctx, u.ID, a.Sealer.SealString(secret), false); err != nil {
		return "", "", "", err
	}
	return secret, uri, qr, nil
}

// PendingTOTPSecret returns the stored (inactive) secret during setup.
func (a *App) PendingTOTPSecret(u *store.User) (string, error) {
	return a.Sealer.OpenString(u.TOTPSecretEnc)
}

// Enable2FA verifies the first code and activates 2FA. It returns fresh
// recovery codes (shown once).
func (a *App) Enable2FA(ctx context.Context, actor Actor, u *store.User, code string) ([]string, error) {
	secret, err := a.Sealer.OpenString(u.TOTPSecretEnc)
	if err != nil || secret == "" {
		return nil, Errf("Bitte die Einrichtung neu starten")
	}
	step, ok := secure.VerifyTOTP(secret, code, 0, time.Now())
	if !ok {
		return nil, Errf("Der Code ist ungültig")
	}
	if err := a.DB.SetTOTP(ctx, u.ID, u.TOTPSecretEnc, true); err != nil {
		return nil, err
	}
	_ = a.DB.SetTOTPLastStep(ctx, u.ID, step)
	codes, err := a.NewRecoveryCodes(ctx, u)
	if err != nil {
		return nil, err
	}
	a.Audit(ctx, actor, 0, "user.2fa_enable", u.Username)
	return codes, nil
}

// Disable2FA turns 2FA off after verifying a current code.
func (a *App) Disable2FA(ctx context.Context, actor Actor, u *store.User, code string) error {
	if !a.Verify2FA(ctx, u, code) {
		return Errf("Der Code ist ungültig")
	}
	if err := a.DB.SetTOTP(ctx, u.ID, nil, false); err != nil {
		return err
	}
	_ = a.DB.ReplaceRecoveryCodes(ctx, u.ID, nil)
	a.Audit(ctx, actor, 0, "user.2fa_disable", u.Username)
	return nil
}

// NewRecoveryCodes generates 10 recovery codes.
func (a *App) NewRecoveryCodes(ctx context.Context, u *store.User) ([]string, error) {
	codes := make([]string, 10)
	hashes := make([]string, 10)
	for i := range codes {
		codes[i] = secure.RandomCode(3)
		hashes[i] = secure.HashToken(strings.ToLower(codes[i]))
	}
	if err := a.DB.ReplaceRecoveryCodes(ctx, u.ID, hashes); err != nil {
		return nil, err
	}
	return codes, nil
}

// Verify2FA checks a TOTP or recovery code.
func (a *App) Verify2FA(ctx context.Context, u *store.User, code string) bool {
	code = strings.TrimSpace(code)
	if len(code) == 14 && strings.Count(code, "-") == 2 {
		ok, err := a.DB.UseRecoveryCode(ctx, u.ID, secure.HashToken(strings.ToLower(code)))
		return err == nil && ok
	}
	secret, err := a.Sealer.OpenString(u.TOTPSecretEnc)
	if err != nil || secret == "" {
		return false
	}
	step, ok := secure.VerifyTOTP(secret, code, u.TOTPLastStep, time.Now())
	if !ok {
		return false
	}
	_ = a.DB.SetTOTPLastStep(ctx, u.ID, step)
	return true
}

// ---- setup token ----

// NewSetupToken generates the one-time token required for the initial
// superadmin setup in the browser.
func (a *App) NewSetupToken(ctx context.Context) (string, error) {
	t := secure.RandomCode(4)
	if err := a.DB.SetSetting(ctx, SetSetupTokenHash, secure.HashToken(t)); err != nil {
		return "", err
	}
	return t, nil
}

// CheckSetupToken validates the setup token.
func (a *App) CheckSetupToken(ctx context.Context, t string) bool {
	h := a.DB.GetSetting(ctx, SetSetupTokenHash, "")
	return h != "" && secure.ConstantTimeEqual(h, secure.HashToken(strings.TrimSpace(strings.ToLower(t))))
}

// ClearSetupToken removes the setup token after use.
func (a *App) ClearSetupToken(ctx context.Context) { _ = a.DB.DeleteSetting(ctx, SetSetupTokenHash) }
