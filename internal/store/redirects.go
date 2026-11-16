package store

import "context"

// Redirect answers every request of a domain with an HTTP redirect to a
// URL (another subdomain, another domain, any https/http address). It is
// not bound to an instance; it belongs to the user who created it.
type Redirect struct {
	ID          int64
	OwnerID     int64
	Domain      string
	URL         string
	Code        int // 301, 302, 307 or 308
	KeepPath    bool
	AllowCIDRs  string
	Enabled     bool
	Description string
	CreatedAt   int64
	UpdatedAt   int64
}

const redirectCols = `id, owner_id, domain, url, code, keep_path, allow_cidrs, enabled, description, created_at, updated_at`

func scanRedirect(row interface{ Scan(...any) error }) (*Redirect, error) {
	r := &Redirect{}
	var keep, enabled int
	err := row.Scan(&r.ID, &r.OwnerID, &r.Domain, &r.URL, &r.Code, &keep, &r.AllowCIDRs, &enabled, &r.Description,
		&r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, notFound(err)
	}
	r.KeepPath, r.Enabled = keep == 1, enabled == 1
	return r, nil
}

// CreateRedirect inserts a redirect.
func (s *Store) CreateRedirect(ctx context.Context, r *Redirect) error {
	t := now()
	res, err := s.db.ExecContext(ctx, `INSERT INTO redirects(owner_id,domain,url,code,keep_path,allow_cidrs,enabled,description,
		created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		r.OwnerID, r.Domain, r.URL, r.Code, b2i(r.KeepPath), r.AllowCIDRs, b2i(r.Enabled), r.Description, t, t)
	if err != nil {
		return err
	}
	r.ID, _ = res.LastInsertId()
	r.CreatedAt, r.UpdatedAt = t, t
	return nil
}

// UpdateRedirect stores a redirect.
func (s *Store) UpdateRedirect(ctx context.Context, r *Redirect) error {
	r.UpdatedAt = now()
	_, err := s.db.ExecContext(ctx, `UPDATE redirects SET owner_id=?, domain=?, url=?, code=?, keep_path=?, allow_cidrs=?,
		enabled=?, description=?, updated_at=? WHERE id=?`,
		r.OwnerID, r.Domain, r.URL, r.Code, b2i(r.KeepPath), r.AllowCIDRs, b2i(r.Enabled), r.Description, r.UpdatedAt, r.ID)
	return err
}

// GetRedirect returns a redirect by ID.
func (s *Store) GetRedirect(ctx context.Context, id int64) (*Redirect, error) {
	return scanRedirect(s.db.QueryRowContext(ctx, "SELECT "+redirectCols+" FROM redirects WHERE id=?", id))
}

// DeleteRedirect removes a redirect.
func (s *Store) DeleteRedirect(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM redirects WHERE id=?", id)
	return err
}

// ListRedirects returns the redirects of one owner (ownerID > 0) or all.
func (s *Store) ListRedirects(ctx context.Context, ownerID int64) ([]*Redirect, error) {
	q := "SELECT " + redirectCols + " FROM redirects"
	var args []any
	if ownerID > 0 {
		q += " WHERE owner_id=?"
		args = append(args, ownerID)
	}
	q += " ORDER BY domain"
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Redirect
	for rows.Next() {
		r, err := scanRedirect(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
