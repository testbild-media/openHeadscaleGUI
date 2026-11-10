package store

import (
	"context"
	"database/sql"
	"errors"
)

// SaveAuthKey stores the encrypted copy of a pre-auth key.
func (s *Store) SaveAuthKey(ctx context.Context, instanceID, keyID int64, enc []byte, expiresAt int64) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO auth_keys(instance_id,key_id,key_enc,expires_at,created_at) VALUES(?,?,?,?,?)
		ON CONFLICT(instance_id,key_id) DO UPDATE SET key_enc=excluded.key_enc, expires_at=excluded.expires_at`,
		instanceID, keyID, enc, expiresAt, now())
	return err
}

// GetAuthKey returns the encrypted copy of a pre-auth key.
func (s *Store) GetAuthKey(ctx context.Context, instanceID, keyID int64) ([]byte, error) {
	var enc []byte
	err := s.db.QueryRowContext(ctx, "SELECT key_enc FROM auth_keys WHERE instance_id=? AND key_id=?", instanceID, keyID).Scan(&enc)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return enc, err
}

// AuthKeyIDs returns the IDs of all stored keys of an instance, mapped to
// the time (unix) the copy was stored.
func (s *Store) AuthKeyIDs(ctx context.Context, instanceID int64) (map[int64]int64, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT key_id, created_at FROM auth_keys WHERE instance_id=?", instanceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]int64{}
	for rows.Next() {
		var id, created int64
		if err := rows.Scan(&id, &created); err != nil {
			return nil, err
		}
		out[id] = created
	}
	return out, rows.Err()
}

// DeleteAuthKey removes the stored copy of a key.
func (s *Store) DeleteAuthKey(ctx context.Context, instanceID, keyID int64) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM auth_keys WHERE instance_id=? AND key_id=?", instanceID, keyID)
	return err
}

// PurgeAuthKeys removes copies of keys that expired before the given time.
func (s *Store) PurgeAuthKeys(ctx context.Context, before int64) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM auth_keys WHERE expires_at < ?", before)
	return err
}
