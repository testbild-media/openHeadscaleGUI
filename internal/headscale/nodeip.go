package headscale

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"net/url"

	_ "modernc.org/sqlite" // headscale uses SQLite
)

// IPChange describes a new address assignment for one node.
type IPChange struct {
	NodeID uint64
	IPv4   string // "" = unchanged
	IPv6   string // "" = unchanged
}

// ApplyIPChanges writes node addresses directly into a headscale SQLite
// database. Headscale MUST be stopped while this runs, because it keeps the
// node table in memory.
func ApplyIPChanges(ctx context.Context, dbPath string, changes []IPChange) error {
	if len(changes) == 0 {
		return nil
	}
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(10000)")
	q.Add("_pragma", "foreign_keys(1)")
	db, err := sql.Open("sqlite", "file:"+dbPath+"?"+q.Encode())
	if err != nil {
		return err
	}
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Pass 1: clear the addresses that will be reassigned so swaps between
	// nodes do not collide.
	for _, c := range changes {
		if c.IPv4 != "" {
			if _, err := tx.ExecContext(ctx, "UPDATE nodes SET ipv4=NULL WHERE id=?", c.NodeID); err != nil {
				return err
			}
		}
		if c.IPv6 != "" {
			if _, err := tx.ExecContext(ctx, "UPDATE nodes SET ipv6=NULL WHERE id=?", c.NodeID); err != nil {
				return err
			}
		}
	}
	for _, c := range changes {
		if c.IPv4 != "" {
			a, err := netip.ParseAddr(c.IPv4)
			if err != nil || !a.Is4() {
				return fmt.Errorf("invalid IPv4 %q", c.IPv4)
			}
			var n int
			if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM nodes WHERE ipv4=? AND id<>?", a.String(), c.NodeID).Scan(&n); err != nil {
				return err
			}
			if n > 0 {
				return fmt.Errorf("IPv4 %s is already used by another node", a)
			}
			res, err := tx.ExecContext(ctx, "UPDATE nodes SET ipv4=? WHERE id=?", a.String(), c.NodeID)
			if err != nil {
				return err
			}
			if rows, _ := res.RowsAffected(); rows != 1 {
				return errors.New("node not found in headscale database")
			}
		}
		if c.IPv6 != "" {
			a, err := netip.ParseAddr(c.IPv6)
			if err != nil || !a.Is6() {
				return fmt.Errorf("invalid IPv6 %q", c.IPv6)
			}
			var n int
			if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM nodes WHERE ipv6=? AND id<>?", a.String(), c.NodeID).Scan(&n); err != nil {
				return err
			}
			if n > 0 {
				return fmt.Errorf("IPv6 %s is already used by another node", a)
			}
			if _, err := tx.ExecContext(ctx, "UPDATE nodes SET ipv6=? WHERE id=?", a.String(), c.NodeID); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

// FirstHost returns the first usable host address of a prefix (network+1),
// which ohg reserves for its own gateway node.
func FirstHost(prefix string) (netip.Addr, error) {
	p, err := netip.ParsePrefix(prefix)
	if err != nil {
		return netip.Addr{}, err
	}
	return p.Masked().Addr().Next(), nil
}
