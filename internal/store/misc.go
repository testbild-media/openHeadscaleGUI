package store

import (
	"context"
	"strings"
)

// ---- pending registrations ----

// Pending registration states.
const (
	PendingOpen     = "pending"
	PendingApproved = "approved"
	PendingRejected = "rejected"
	PendingExpired  = "expired"
)

// PendingRegistration is an interactive login waiting for approval.
type PendingRegistration struct {
	ID         int64
	InstanceID int64
	AuthID     string
	SourceIP   string
	UserAgent  string
	Status     string
	CreatedAt  int64
	DecidedBy  int64
	DecidedAt  int64
	NodeID     int64
	Note       string
}

const pendingCols = "id, instance_id, auth_id, source_ip, user_agent, status, created_at, decided_by, decided_at, node_id, note"

func scanPending(row interface{ Scan(...any) error }) (*PendingRegistration, error) {
	p := &PendingRegistration{}
	err := row.Scan(&p.ID, &p.InstanceID, &p.AuthID, &p.SourceIP, &p.UserAgent, &p.Status, &p.CreatedAt, &p.DecidedBy, &p.DecidedAt, &p.NodeID, &p.Note)
	return p, notFound(err)
}

// UpsertPending records a registration request (idempotent per auth ID).
// It returns false if the instance already has too many open requests.
func (s *Store) UpsertPending(ctx context.Context, p *PendingRegistration, maxOpen int) (bool, error) {
	var exists int
	_ = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM pending_registrations WHERE instance_id=? AND auth_id=?", p.InstanceID, p.AuthID).Scan(&exists)
	if exists > 0 {
		return true, nil
	}
	var open int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM pending_registrations WHERE instance_id=? AND status='pending'", p.InstanceID).Scan(&open); err != nil {
		return false, err
	}
	if open >= maxOpen {
		return false, nil
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO pending_registrations(instance_id,auth_id,source_ip,user_agent,status,created_at)
		VALUES(?,?,?,?,'pending',?)`, p.InstanceID, p.AuthID, p.SourceIP, truncate(p.UserAgent, 200), now())
	return err == nil, err
}

// GetPending returns one pending registration.
func (s *Store) GetPending(ctx context.Context, id int64) (*PendingRegistration, error) {
	return scanPending(s.db.QueryRowContext(ctx, "SELECT "+pendingCols+" FROM pending_registrations WHERE id=?", id))
}

// ListPending lists registrations of an instance; onlyOpen filters to pending.
func (s *Store) ListPending(ctx context.Context, instanceID int64, onlyOpen bool, limit int) ([]*PendingRegistration, error) {
	q := "SELECT " + pendingCols + " FROM pending_registrations WHERE instance_id=?"
	if onlyOpen {
		q += " AND status='pending'"
	}
	q += " ORDER BY created_at DESC LIMIT ?"
	rows, err := s.db.QueryContext(ctx, q, instanceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*PendingRegistration
	for rows.Next() {
		p, err := scanPending(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// CountOpenPending counts open registrations per instance.
func (s *Store) CountOpenPending(ctx context.Context) (map[int64]int, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT instance_id, COUNT(*) FROM pending_registrations WHERE status='pending' GROUP BY instance_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]int{}
	for rows.Next() {
		var id int64
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

// DecidePending updates the state of a registration.
func (s *Store) DecidePending(ctx context.Context, id int64, status string, by int64, nodeID int64, note string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE pending_registrations SET status=?, decided_by=?, decided_at=?, node_id=?, note=? WHERE id=?",
		status, by, now(), nodeID, truncate(note, 300), id)
	return err
}

// ExpirePending marks old open requests as expired and deletes very old rows.
func (s *Store) ExpirePending(ctx context.Context, olderThan, deleteBefore int64) error {
	if _, err := s.db.ExecContext(ctx, "UPDATE pending_registrations SET status='expired' WHERE status='pending' AND created_at < ?", olderThan); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, "DELETE FROM pending_registrations WHERE status<>'pending' AND created_at < ?", deleteBefore)
	return err
}

// ---- client profiles ----

// Client profile states.
const (
	ProfileWaiting    = "waiting"
	ProfileRegistered = "registered"
	ProfileApplied    = "applied"
	ProfileError      = "error"
)

// ClientProfile describes a planned client: when a node registers with the
// profile's pre-auth key, name, fixed IP and route approvals are applied.
type ClientProfile struct {
	ID           int64
	InstanceID   int64
	Name         string
	HSUser       string
	DesiredIPv4  string
	PreAuthKeyID int64
	NodeID       int64
	AutoExit     bool
	AutoRoutes   string
	Status       string
	LastError    string
	CreatedAt    int64
	UpdatedAt    int64
}

// AutoRouteList returns the configured auto-approved routes.
func (p *ClientProfile) AutoRouteList() []string {
	var out []string
	for _, r := range strings.FieldsFunc(p.AutoRoutes, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		if r = strings.TrimSpace(r); r != "" {
			out = append(out, r)
		}
	}
	return out
}

const profileCols = "id, instance_id, name, hs_user, desired_ipv4, preauth_key_id, node_id, auto_exit, auto_routes, status, last_error, created_at, updated_at"

func scanProfile(row interface{ Scan(...any) error }) (*ClientProfile, error) {
	p := &ClientProfile{}
	var exit int
	err := row.Scan(&p.ID, &p.InstanceID, &p.Name, &p.HSUser, &p.DesiredIPv4, &p.PreAuthKeyID, &p.NodeID, &exit, &p.AutoRoutes,
		&p.Status, &p.LastError, &p.CreatedAt, &p.UpdatedAt)
	p.AutoExit = exit == 1
	return p, notFound(err)
}

// CreateProfile inserts a client profile.
func (s *Store) CreateProfile(ctx context.Context, p *ClientProfile) error {
	t := now()
	res, err := s.db.ExecContext(ctx, `INSERT INTO client_profiles(instance_id,name,hs_user,desired_ipv4,preauth_key_id,node_id,auto_exit,auto_routes,status,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)`, p.InstanceID, p.Name, p.HSUser, p.DesiredIPv4, p.PreAuthKeyID, p.NodeID, b2i(p.AutoExit), p.AutoRoutes, p.Status, t, t)
	if err != nil {
		return err
	}
	p.ID, _ = res.LastInsertId()
	return nil
}

// UpdateProfile stores a client profile.
func (s *Store) UpdateProfile(ctx context.Context, p *ClientProfile) error {
	_, err := s.db.ExecContext(ctx, `UPDATE client_profiles SET name=?, hs_user=?, desired_ipv4=?, preauth_key_id=?, node_id=?, auto_exit=?,
		auto_routes=?, status=?, last_error=?, updated_at=? WHERE id=?`, p.Name, p.HSUser, p.DesiredIPv4, p.PreAuthKeyID, p.NodeID,
		b2i(p.AutoExit), p.AutoRoutes, p.Status, truncate(p.LastError, 500), now(), p.ID)
	return err
}

// GetProfile returns a profile by ID.
func (s *Store) GetProfile(ctx context.Context, id int64) (*ClientProfile, error) {
	return scanProfile(s.db.QueryRowContext(ctx, "SELECT "+profileCols+" FROM client_profiles WHERE id=?", id))
}

// ListProfiles returns the profiles of an instance.
func (s *Store) ListProfiles(ctx context.Context, instanceID int64) ([]*ClientProfile, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+profileCols+" FROM client_profiles WHERE instance_id=? ORDER BY name", instanceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ClientProfile
	for rows.Next() {
		p, err := scanProfile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// DeleteProfile removes a profile.
func (s *Store) DeleteProfile(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM client_profiles WHERE id=?", id)
	return err
}

// ---- audit ----

// AuditEntry is one audit log row.
type AuditEntry struct {
	ID         int64
	TS         int64
	UserID     int64
	Username   string
	IP         string
	InstanceID int64
	Action     string
	Detail     string
}

// Audit appends an audit entry.
func (s *Store) Audit(ctx context.Context, e AuditEntry) error {
	if e.TS == 0 {
		e.TS = now()
	}
	_, err := s.db.ExecContext(ctx, "INSERT INTO audit_log(ts,user_id,username,ip,instance_id,action,detail) VALUES(?,?,?,?,?,?,?)",
		e.TS, e.UserID, e.Username, e.IP, e.InstanceID, e.Action, truncate(e.Detail, 1000))
	return err
}

// ListAudit returns audit entries; instanceIDs restricts to those instances
// (nil = all). userID > 0 additionally includes the user's own actions.
func (s *Store) ListAudit(ctx context.Context, instanceIDs []int64, userID int64, limit, offset int) ([]*AuditEntry, error) {
	q := "SELECT id, ts, user_id, username, ip, instance_id, action, detail FROM audit_log"
	var args []any
	if instanceIDs != nil {
		var conds []string
		if len(instanceIDs) > 0 {
			ph := strings.Repeat("?,", len(instanceIDs))
			conds = append(conds, "instance_id IN ("+ph[:len(ph)-1]+")")
			for _, id := range instanceIDs {
				args = append(args, id)
			}
		}
		if userID > 0 {
			conds = append(conds, "user_id=?")
			args = append(args, userID)
		}
		if len(conds) == 0 {
			return nil, nil
		}
		q += " WHERE " + strings.Join(conds, " OR ")
	}
	q += " ORDER BY id DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AuditEntry
	for rows.Next() {
		e := &AuditEntry{}
		if err := rows.Scan(&e.ID, &e.TS, &e.UserID, &e.Username, &e.IP, &e.InstanceID, &e.Action, &e.Detail); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// PurgeAudit deletes entries older than ts.
func (s *Store) PurgeAudit(ctx context.Context, before int64) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM audit_log WHERE ts < ?", before)
	return err
}

// ---- DERP keys ----

// DERPKey is a manual allow/deny entry for the DERP admission controller.
type DERPKey struct {
	NodeKey   string
	Mode      string
	Note      string
	CreatedAt int64
}

// ListDERPKeys returns all manual DERP key entries.
func (s *Store) ListDERPKeys(ctx context.Context) ([]*DERPKey, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT node_key, mode, note, created_at FROM derp_keys ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*DERPKey
	for rows.Next() {
		k := &DERPKey{}
		if err := rows.Scan(&k.NodeKey, &k.Mode, &k.Note, &k.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// SetDERPKey adds or replaces an entry.
func (s *Store) SetDERPKey(ctx context.Context, k *DERPKey) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO derp_keys(node_key,mode,note,created_at) VALUES(?,?,?,?)
		ON CONFLICT(node_key) DO UPDATE SET mode=excluded.mode, note=excluded.note`, k.NodeKey, k.Mode, truncate(k.Note, 200), now())
	return err
}

// DeleteDERPKey removes an entry.
func (s *Store) DeleteDERPKey(ctx context.Context, nodeKey string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM derp_keys WHERE node_key=?", nodeKey)
	return err
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
