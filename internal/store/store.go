// Package store persists the ohg state in SQLite.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"

	_ "modernc.org/sqlite" // SQLite driver (pure Go)
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// Store wraps the SQLite database.
type Store struct {
	db *sql.DB
}

// Open opens (and migrates) the database at path.
func Open(path string) (*Store, error) {
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(10000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "synchronous(NORMAL)")
	q.Add("_pragma", "secure_delete(1)")
	db, err := sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	// A single connection serializes access and avoids SQLITE_BUSY inside
	// the process. All queries are short.
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// DB exposes the raw handle (used by tests).
func (s *Store) DB() *sql.DB { return s.db }

func now() int64 { return time.Now().Unix() }

var migrations = []string{
	// 1: initial schema
	`
CREATE TABLE users (
	id INTEGER PRIMARY KEY,
	username TEXT NOT NULL UNIQUE COLLATE NOCASE,
	email TEXT NOT NULL DEFAULT '',
	password_hash TEXT NOT NULL,
	role TEXT NOT NULL CHECK (role IN ('superadmin','user')),
	disabled INTEGER NOT NULL DEFAULT 0,
	totp_secret_enc BLOB,
	totp_enabled INTEGER NOT NULL DEFAULT 0,
	totp_last_step INTEGER NOT NULL DEFAULT 0,
	max_instances INTEGER NOT NULL DEFAULT 3,
	failed_logins INTEGER NOT NULL DEFAULT 0,
	locked_until INTEGER NOT NULL DEFAULT 0,
	must_change_password INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL,
	last_login_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE recovery_codes (
	id INTEGER PRIMARY KEY,
	user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	code_hash TEXT NOT NULL,
	used_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX recovery_codes_user ON recovery_codes(user_id);
CREATE TABLE sessions (
	id_hash TEXT PRIMARY KEY,
	user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	csrf TEXT NOT NULL,
	mfa_pending INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL,
	last_seen_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	ip TEXT NOT NULL DEFAULT '',
	user_agent TEXT NOT NULL DEFAULT ''
);
CREATE INDEX sessions_user ON sessions(user_id);
CREATE TABLE instances (
	id INTEGER PRIMARY KEY,
	slug TEXT NOT NULL UNIQUE,
	name TEXT NOT NULL,
	owner_id INTEGER NOT NULL REFERENCES users(id),
	domain TEXT NOT NULL UNIQUE,
	enabled INTEGER NOT NULL DEFAULT 1,
	internal_port INTEGER NOT NULL UNIQUE,
	gateway_port INTEGER NOT NULL UNIQUE,
	prefix_v4 TEXT NOT NULL,
	prefix_v6 TEXT NOT NULL,
	ip_allocation TEXT NOT NULL DEFAULT 'sequential',
	magic_dns INTEGER NOT NULL DEFAULT 1,
	base_domain TEXT NOT NULL,
	nameservers TEXT NOT NULL DEFAULT '1.1.1.1,9.9.9.9',
	override_local_dns INTEGER NOT NULL DEFAULT 0,
	use_central_derp INTEGER NOT NULL DEFAULT 1,
	use_public_derp INTEGER NOT NULL DEFAULT 0,
	gateway_exit_node INTEGER NOT NULL DEFAULT 1,
	node_expiry TEXT NOT NULL DEFAULT '0',
	ephemeral_timeout TEXT NOT NULL DEFAULT '30m',
	api_key_enc BLOB,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);
CREATE TABLE forwards (
	id INTEGER PRIMARY KEY,
	instance_id INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
	kind TEXT NOT NULL CHECK (kind IN ('http','tcp','udp')),
	domain TEXT,
	public_port INTEGER NOT NULL DEFAULT 0,
	node_id INTEGER NOT NULL DEFAULT 0,
	target_host TEXT NOT NULL DEFAULT '',
	target_port INTEGER NOT NULL,
	upstream_tls INTEGER NOT NULL DEFAULT 0,
	upstream_insecure INTEGER NOT NULL DEFAULT 0,
	preserve_host INTEGER NOT NULL DEFAULT 1,
	allow_cidrs TEXT NOT NULL DEFAULT '',
	basic_auth_user TEXT NOT NULL DEFAULT '',
	basic_auth_hash TEXT NOT NULL DEFAULT '',
	enabled INTEGER NOT NULL DEFAULT 1,
	description TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX forwards_domain ON forwards(domain) WHERE domain IS NOT NULL AND domain <> '';
CREATE UNIQUE INDEX forwards_port ON forwards(kind, public_port) WHERE kind <> 'http';
CREATE INDEX forwards_instance ON forwards(instance_id);
CREATE TABLE pending_registrations (
	id INTEGER PRIMARY KEY,
	instance_id INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
	auth_id TEXT NOT NULL,
	source_ip TEXT NOT NULL DEFAULT '',
	user_agent TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL DEFAULT 'pending',
	created_at INTEGER NOT NULL,
	decided_by INTEGER NOT NULL DEFAULT 0,
	decided_at INTEGER NOT NULL DEFAULT 0,
	node_id INTEGER NOT NULL DEFAULT 0,
	note TEXT NOT NULL DEFAULT '',
	UNIQUE (instance_id, auth_id)
);
CREATE TABLE client_profiles (
	id INTEGER PRIMARY KEY,
	instance_id INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
	name TEXT NOT NULL,
	hs_user TEXT NOT NULL,
	desired_ipv4 TEXT NOT NULL DEFAULT '',
	preauth_key_id INTEGER NOT NULL DEFAULT 0,
	node_id INTEGER NOT NULL DEFAULT 0,
	auto_exit INTEGER NOT NULL DEFAULT 0,
	auto_routes TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL DEFAULT 'waiting',
	last_error TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);
CREATE INDEX client_profiles_instance ON client_profiles(instance_id);
CREATE TABLE audit_log (
	id INTEGER PRIMARY KEY,
	ts INTEGER NOT NULL,
	user_id INTEGER NOT NULL DEFAULT 0,
	username TEXT NOT NULL DEFAULT '',
	ip TEXT NOT NULL DEFAULT '',
	instance_id INTEGER NOT NULL DEFAULT 0,
	action TEXT NOT NULL,
	detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX audit_ts ON audit_log(ts);
CREATE INDEX audit_instance ON audit_log(instance_id);
CREATE TABLE settings (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE derp_keys (
	node_key TEXT PRIMARY KEY,
	mode TEXT NOT NULL CHECK (mode IN ('allow','deny')),
	note TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL
);
`,
	// 2: encrypted copies of pre-auth keys created in the GUI, so that the
	// connect command can be shown again later (headscale stores only a hash)
	`
CREATE TABLE auth_keys (
	instance_id INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
	key_id INTEGER NOT NULL,
	key_enc BLOB NOT NULL,
	expires_at INTEGER NOT NULL,
	created_at INTEGER NOT NULL,
	PRIMARY KEY (instance_id, key_id)
);
`,
	// 3: forwards to services on the server itself (superadmin only) and
	// plain redirects; the table is rebuilt for the new kind
	`
CREATE TABLE forwards_new (
	id INTEGER PRIMARY KEY,
	instance_id INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
	kind TEXT NOT NULL CHECK (kind IN ('http','tcp','udp','redirect')),
	domain TEXT,
	public_port INTEGER NOT NULL DEFAULT 0,
	node_id INTEGER NOT NULL DEFAULT 0,
	target_host TEXT NOT NULL DEFAULT '',
	target_port INTEGER NOT NULL DEFAULT 0,
	upstream_tls INTEGER NOT NULL DEFAULT 0,
	upstream_insecure INTEGER NOT NULL DEFAULT 0,
	preserve_host INTEGER NOT NULL DEFAULT 1,
	allow_cidrs TEXT NOT NULL DEFAULT '',
	basic_auth_user TEXT NOT NULL DEFAULT '',
	basic_auth_hash TEXT NOT NULL DEFAULT '',
	enabled INTEGER NOT NULL DEFAULT 1,
	description TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL,
	local_target INTEGER NOT NULL DEFAULT 0,
	redirect_url TEXT NOT NULL DEFAULT '',
	redirect_code INTEGER NOT NULL DEFAULT 302,
	redirect_keep_path INTEGER NOT NULL DEFAULT 1
);
INSERT INTO forwards_new (id, instance_id, kind, domain, public_port, node_id, target_host, target_port, upstream_tls,
	upstream_insecure, preserve_host, allow_cidrs, basic_auth_user, basic_auth_hash, enabled, description, created_at, updated_at)
SELECT id, instance_id, kind, domain, public_port, node_id, target_host, target_port, upstream_tls,
	upstream_insecure, preserve_host, allow_cidrs, basic_auth_user, basic_auth_hash, enabled, description, created_at, updated_at
FROM forwards;
DROP TABLE forwards;
ALTER TABLE forwards_new RENAME TO forwards;
CREATE UNIQUE INDEX forwards_domain ON forwards(domain) WHERE domain IS NOT NULL AND domain <> '';
CREATE UNIQUE INDEX forwards_port ON forwards(kind, public_port) WHERE kind IN ('tcp','udp');
CREATE INDEX forwards_instance ON forwards(instance_id);
`,
	// 4: bridges publish a service of one instance into another instance
	// (on the server's .1 address there, only for selected clients), and
	// instances can isolate their clients from each other
	`
ALTER TABLE instances ADD COLUMN isolate_clients INTEGER NOT NULL DEFAULT 0;
CREATE TABLE bridges (
	id INTEGER PRIMARY KEY,
	name TEXT NOT NULL DEFAULT '',
	from_instance_id INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
	node_id INTEGER NOT NULL DEFAULT 0,
	target_host TEXT NOT NULL DEFAULT '',
	target_port INTEGER NOT NULL,
	proto TEXT NOT NULL CHECK (proto IN ('tcp','udp')),
	to_instance_id INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
	listen_port INTEGER NOT NULL,
	allow_all INTEGER NOT NULL DEFAULT 0,
	allowed_nodes TEXT NOT NULL DEFAULT '',
	enabled INTEGER NOT NULL DEFAULT 1,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX bridges_listen ON bridges(to_instance_id, proto, listen_port);
CREATE INDEX bridges_from ON bridges(from_instance_id);
`,
	// 5: host bridges make a whole device reachable (all ports) under a
	// virtual address from the bridge network of the target instance
	`
ALTER TABLE instances ADD COLUMN bridge_prefix TEXT NOT NULL DEFAULT '198.18.0.0/24';
ALTER TABLE bridges ADD COLUMN mode TEXT NOT NULL DEFAULT 'port';
ALTER TABLE bridges ADD COLUMN virtual_ip TEXT NOT NULL DEFAULT '';
ALTER TABLE bridges ADD COLUMN dns_name TEXT NOT NULL DEFAULT '';
DROP INDEX bridges_listen;
CREATE UNIQUE INDEX bridges_listen ON bridges(to_instance_id, proto, listen_port) WHERE mode = 'port';
CREATE UNIQUE INDEX bridges_vip ON bridges(to_instance_id, virtual_ip) WHERE mode = 'host';
`,
	// 6: redirects get their own table (not bound to an instance); the
	// redirect forwards of earlier versions move over to their owner
	`
CREATE TABLE redirects (
	id INTEGER PRIMARY KEY,
	owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	domain TEXT NOT NULL UNIQUE,
	url TEXT NOT NULL,
	code INTEGER NOT NULL DEFAULT 302,
	keep_path INTEGER NOT NULL DEFAULT 1,
	allow_cidrs TEXT NOT NULL DEFAULT '',
	enabled INTEGER NOT NULL DEFAULT 1,
	description TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);
INSERT INTO redirects (owner_id, domain, url, code, keep_path, allow_cidrs, enabled, description, created_at, updated_at)
SELECT i.owner_id, f.domain, f.redirect_url, f.redirect_code, f.redirect_keep_path, f.allow_cidrs, f.enabled, f.description,
	f.created_at, f.updated_at
FROM forwards f JOIN instances i ON i.id = f.instance_id
WHERE f.kind = 'redirect' AND f.domain IS NOT NULL AND f.domain <> '' AND f.redirect_url <> '';
DELETE FROM forwards WHERE kind = 'redirect';
`,
}

func (s *Store) migrate(ctx context.Context) error {
	var version int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	for i := version; i < len(migrations); i++ {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		if _, err := tx.ExecContext(ctx, "PRAGMA user_version = "+strconv.Itoa(i+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ---- settings ----

// GetSetting returns a setting or def if unset.
func (s *Store) GetSetting(ctx context.Context, key, def string) string {
	var v string
	err := s.db.QueryRowContext(ctx, "SELECT value FROM settings WHERE key=?", key).Scan(&v)
	if err != nil {
		return def
	}
	return v
}

// GetSettingBool returns a boolean setting.
func (s *Store) GetSettingBool(ctx context.Context, key string, def bool) bool {
	v := s.GetSetting(ctx, key, "")
	if v == "" {
		return def
	}
	return v == "1" || v == "true"
}

// GetSettingInt returns an integer setting.
func (s *Store) GetSettingInt(ctx context.Context, key string, def int) int {
	v := s.GetSetting(ctx, key, "")
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

// SetSetting stores a setting.
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, "INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", key, value)
	return err
}

// SetSettings stores several settings atomically.
func (s *Store) SetSettings(ctx context.Context, kv map[string]string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	for k, v := range kv {
		if _, err := tx.ExecContext(ctx, "INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", k, v); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// DeleteSetting removes a setting.
func (s *Store) DeleteSetting(ctx context.Context, key string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM settings WHERE key=?", key)
	return err
}

func notFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}
