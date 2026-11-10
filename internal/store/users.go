package store

import (
	"context"
	"database/sql"
	"time"
)

// Roles.
const (
	RoleSuperadmin = "superadmin"
	RoleUser       = "user"
)

// User is a GUI account.
type User struct {
	ID                 int64
	Username           string
	Email              string
	PasswordHash       string
	Role               string
	Disabled           bool
	TOTPSecretEnc      []byte
	TOTPEnabled        bool
	TOTPLastStep       int64
	MaxInstances       int
	FailedLogins       int
	LockedUntil        int64
	MustChangePassword bool
	CreatedAt          int64
	UpdatedAt          int64
	LastLoginAt        int64
}

// IsSuperadmin reports whether the user has full access.
func (u *User) IsSuperadmin() bool { return u != nil && u.Role == RoleSuperadmin }

// Locked reports whether the account is temporarily locked.
func (u *User) Locked(t time.Time) bool { return u.LockedUntil > t.Unix() }

const userCols = `id, username, email, password_hash, role, disabled, totp_secret_enc, totp_enabled,
	totp_last_step, max_instances, failed_logins, locked_until, must_change_password, created_at, updated_at, last_login_at`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	u := &User{}
	var disabled, totp, mcp int
	err := row.Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.Role, &disabled, &u.TOTPSecretEnc, &totp,
		&u.TOTPLastStep, &u.MaxInstances, &u.FailedLogins, &u.LockedUntil, &mcp, &u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt)
	if err != nil {
		return nil, notFound(err)
	}
	u.Disabled, u.TOTPEnabled, u.MustChangePassword = disabled == 1, totp == 1, mcp == 1
	return u, nil
}

// CountUsers returns the number of users.
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&n)
	return n, err
}

// CreateUser inserts a user and sets its ID.
func (s *Store) CreateUser(ctx context.Context, u *User) error {
	t := now()
	res, err := s.db.ExecContext(ctx, `INSERT INTO users(username,email,password_hash,role,disabled,max_instances,must_change_password,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?)`, u.Username, u.Email, u.PasswordHash, u.Role, b2i(u.Disabled), u.MaxInstances, b2i(u.MustChangePassword), t, t)
	if err != nil {
		return err
	}
	u.ID, _ = res.LastInsertId()
	u.CreatedAt, u.UpdatedAt = t, t
	return nil
}

// GetUser returns a user by ID.
func (s *Store) GetUser(ctx context.Context, id int64) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, "SELECT "+userCols+" FROM users WHERE id=?", id))
}

// GetUserByName returns a user by username (case insensitive).
func (s *Store) GetUserByName(ctx context.Context, name string) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, "SELECT "+userCols+" FROM users WHERE username=?", name))
}

// ListUsers returns all users.
func (s *Store) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+userCols+" FROM users ORDER BY username")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// UpdateUserProfile updates editable account fields.
func (s *Store) UpdateUserProfile(ctx context.Context, u *User) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET email=?, role=?, disabled=?, max_instances=?, updated_at=? WHERE id=?`,
		u.Email, u.Role, b2i(u.Disabled), u.MaxInstances, now(), u.ID)
	return err
}

// SetPassword replaces the password hash.
func (s *Store) SetPassword(ctx context.Context, id int64, hash string, mustChange bool) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET password_hash=?, must_change_password=?, failed_logins=0, locked_until=0, updated_at=? WHERE id=?`,
		hash, b2i(mustChange), now(), id)
	return err
}

// SetTOTP stores (or clears) the TOTP secret.
func (s *Store) SetTOTP(ctx context.Context, id int64, secretEnc []byte, enabled bool) error {
	var v any = secretEnc
	if secretEnc == nil {
		v = nil
	}
	_, err := s.db.ExecContext(ctx, `UPDATE users SET totp_secret_enc=?, totp_enabled=?, totp_last_step=0, updated_at=? WHERE id=?`,
		v, b2i(enabled), now(), id)
	return err
}

// SetTOTPLastStep records the last used TOTP step (replay protection).
func (s *Store) SetTOTPLastStep(ctx context.Context, id, step int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET totp_last_step=? WHERE id=? AND totp_last_step < ?`, step, id, step)
	return err
}

// RecordLoginFailure increments the failure counter and applies an
// exponential lock (1 min, 2, 4 … max 60 min) after 5 failures.
func (s *Store) RecordLoginFailure(ctx context.Context, id int64) error {
	u, err := s.GetUser(ctx, id)
	if err != nil {
		return err
	}
	failed := u.FailedLogins + 1
	var locked int64
	if failed >= 5 {
		minutes := 1 << min(failed-5, 6)
		if minutes > 60 {
			minutes = 60
		}
		locked = time.Now().Add(time.Duration(minutes) * time.Minute).Unix()
	}
	_, err = s.db.ExecContext(ctx, `UPDATE users SET failed_logins=?, locked_until=? WHERE id=?`, failed, locked, id)
	return err
}

// RecordLoginSuccess resets the failure counter.
func (s *Store) RecordLoginSuccess(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET failed_logins=0, locked_until=0, last_login_at=? WHERE id=?`, now(), id)
	return err
}

// UnlockUser clears a lock.
func (s *Store) UnlockUser(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET failed_logins=0, locked_until=0 WHERE id=?`, id)
	return err
}

// DeleteUser removes a user (sessions cascade).
func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM users WHERE id=?", id)
	return err
}

// CountSuperadmins returns the number of enabled superadmins.
func (s *Store) CountSuperadmins(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE role='superadmin' AND disabled=0").Scan(&n)
	return n, err
}

// ---- recovery codes ----

// ReplaceRecoveryCodes stores new recovery code hashes for a user.
func (s *Store) ReplaceRecoveryCodes(ctx context.Context, userID int64, hashes []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM recovery_codes WHERE user_id=?", userID); err != nil {
		tx.Rollback()
		return err
	}
	for _, h := range hashes {
		if _, err := tx.ExecContext(ctx, "INSERT INTO recovery_codes(user_id, code_hash) VALUES(?,?)", userID, h); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// UseRecoveryCode marks a matching unused code as used. Returns true on success.
func (s *Store) UseRecoveryCode(ctx context.Context, userID int64, hash string) (bool, error) {
	res, err := s.db.ExecContext(ctx, "UPDATE recovery_codes SET used_at=? WHERE user_id=? AND code_hash=? AND used_at=0", now(), userID, hash)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// CountRecoveryCodes returns the number of unused codes.
func (s *Store) CountRecoveryCodes(ctx context.Context, userID int64) int {
	var n int
	_ = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM recovery_codes WHERE user_id=? AND used_at=0", userID).Scan(&n)
	return n
}

// ---- sessions ----

// Session is a login session; the cookie carries the token, the DB only
// its hash.
type Session struct {
	IDHash     string
	UserID     int64
	CSRF       string
	MFAPending bool
	CreatedAt  int64
	LastSeenAt int64
	ExpiresAt  int64
	IP         string
	UserAgent  string
}

// CreateSession stores a session.
func (s *Store) CreateSession(ctx context.Context, ss *Session) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions(id_hash,user_id,csrf,mfa_pending,created_at,last_seen_at,expires_at,ip,user_agent)
		VALUES(?,?,?,?,?,?,?,?,?)`, ss.IDHash, ss.UserID, ss.CSRF, b2i(ss.MFAPending), ss.CreatedAt, ss.LastSeenAt, ss.ExpiresAt, ss.IP, ss.UserAgent)
	return err
}

func scanSession(row interface{ Scan(...any) error }) (*Session, error) {
	ss := &Session{}
	var mfa int
	if err := row.Scan(&ss.IDHash, &ss.UserID, &ss.CSRF, &mfa, &ss.CreatedAt, &ss.LastSeenAt, &ss.ExpiresAt, &ss.IP, &ss.UserAgent); err != nil {
		return nil, notFound(err)
	}
	ss.MFAPending = mfa == 1
	return ss, nil
}

const sessionCols = "id_hash,user_id,csrf,mfa_pending,created_at,last_seen_at,expires_at,ip,user_agent"

// GetSession returns a session by token hash.
func (s *Store) GetSession(ctx context.Context, idHash string) (*Session, error) {
	return scanSession(s.db.QueryRowContext(ctx, "SELECT "+sessionCols+" FROM sessions WHERE id_hash=?", idHash))
}

// TouchSession updates last_seen_at.
func (s *Store) TouchSession(ctx context.Context, idHash string, t int64) error {
	_, err := s.db.ExecContext(ctx, "UPDATE sessions SET last_seen_at=? WHERE id_hash=?", t, idHash)
	return err
}

// DeleteSession removes one session.
func (s *Store) DeleteSession(ctx context.Context, idHash string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE id_hash=?", idHash)
	return err
}

// DeleteUserSessions removes all sessions of a user except keep (may be "").
func (s *Store) DeleteUserSessions(ctx context.Context, userID int64, keep string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE user_id=? AND id_hash<>?", userID, keep)
	return err
}

// ListUserSessions lists active sessions of a user.
func (s *Store) ListUserSessions(ctx context.Context, userID int64) ([]*Session, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+sessionCols+" FROM sessions WHERE user_id=? AND mfa_pending=0 ORDER BY last_seen_at DESC", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Session
	for rows.Next() {
		ss, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ss)
	}
	return out, rows.Err()
}

// PurgeSessions deletes expired and idle sessions.
func (s *Store) PurgeSessions(ctx context.Context, idleBefore int64) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE expires_at < ? OR last_seen_at < ?", now(), idleBefore)
	return err
}

// nullString converts "" to NULL.
func nullString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}
