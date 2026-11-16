package store

import (
	"context"
	"strconv"
	"strings"
)

// Bridge publishes one service of a device in instance From into instance
// To: it listens on the server's tailnet address (.1) there and only admits
// the selected clients.
type Bridge struct {
	ID   int64
	Name string
	// Mode "host" makes the whole device reachable under VirtualIP (all
	// ports); "port" publishes one port on the server's .1.
	Mode           string
	VirtualIP      string
	DNSName        string // optional MagicDNS name of a host bridge
	FromInstanceID int64
	NodeID         int64  // source device (0 = TargetHost)
	TargetHost     string // IP inside the source tailnet or an approved subnet
	TargetPort     int
	Proto          string // "tcp" or "udp"
	ToInstanceID   int64
	ListenPort     int
	AllowAll       bool
	AllowedNodes   []int64 // node IDs in the target instance
	Enabled        bool
	CreatedAt      int64
	UpdatedAt      int64
}

// Allows reports whether node id of the target instance may use the bridge.
func (b *Bridge) Allows(id int64) bool {
	if b.AllowAll {
		return true
	}
	for _, n := range b.AllowedNodes {
		if n == id {
			return true
		}
	}
	return false
}

const bridgeCols = `id, name, from_instance_id, node_id, target_host, target_port, proto, to_instance_id, listen_port,
	allow_all, allowed_nodes, enabled, created_at, updated_at, mode, virtual_ip, dns_name`

func joinIDs(ids []int64) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, strconv.FormatInt(id, 10))
	}
	return strings.Join(parts, ",")
}

func splitIDs(s string) []int64 {
	var out []int64
	for _, p := range strings.Split(s, ",") {
		if id, err := strconv.ParseInt(strings.TrimSpace(p), 10, 64); err == nil && id > 0 {
			out = append(out, id)
		}
	}
	return out
}

func scanBridge(row interface{ Scan(...any) error }) (*Bridge, error) {
	b := &Bridge{}
	var all, enabled int
	var nodes string
	err := row.Scan(&b.ID, &b.Name, &b.FromInstanceID, &b.NodeID, &b.TargetHost, &b.TargetPort, &b.Proto, &b.ToInstanceID,
		&b.ListenPort, &all, &nodes, &enabled, &b.CreatedAt, &b.UpdatedAt, &b.Mode, &b.VirtualIP, &b.DNSName)
	if err != nil {
		return nil, notFound(err)
	}
	b.AllowAll, b.Enabled, b.AllowedNodes = all == 1, enabled == 1, splitIDs(nodes)
	return b, nil
}

// CreateBridge inserts a bridge.
func (s *Store) CreateBridge(ctx context.Context, b *Bridge) error {
	t := now()
	res, err := s.db.ExecContext(ctx, `INSERT INTO bridges(name,from_instance_id,node_id,target_host,target_port,proto,to_instance_id,
		listen_port,allow_all,allowed_nodes,enabled,created_at,updated_at,mode,virtual_ip,dns_name) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		b.Name, b.FromInstanceID, b.NodeID, b.TargetHost, b.TargetPort, b.Proto, b.ToInstanceID, b.ListenPort,
		b2i(b.AllowAll), joinIDs(b.AllowedNodes), b2i(b.Enabled), t, t, b.modeOrDefault(), b.VirtualIP, b.DNSName)
	if err != nil {
		return err
	}
	b.ID, _ = res.LastInsertId()
	b.CreatedAt, b.UpdatedAt = t, t
	return nil
}

// UpdateBridge stores a bridge.
func (s *Store) UpdateBridge(ctx context.Context, b *Bridge) error {
	b.UpdatedAt = now()
	_, err := s.db.ExecContext(ctx, `UPDATE bridges SET name=?, from_instance_id=?, node_id=?, target_host=?, target_port=?, proto=?,
		to_instance_id=?, listen_port=?, allow_all=?, allowed_nodes=?, enabled=?, updated_at=?, mode=?, virtual_ip=?, dns_name=?
		WHERE id=?`,
		b.Name, b.FromInstanceID, b.NodeID, b.TargetHost, b.TargetPort, b.Proto, b.ToInstanceID, b.ListenPort,
		b2i(b.AllowAll), joinIDs(b.AllowedNodes), b2i(b.Enabled), b.UpdatedAt, b.modeOrDefault(), b.VirtualIP, b.DNSName, b.ID)
	return err
}

// GetBridge returns a bridge by ID.
func (s *Store) GetBridge(ctx context.Context, id int64) (*Bridge, error) {
	return scanBridge(s.db.QueryRowContext(ctx, "SELECT "+bridgeCols+" FROM bridges WHERE id=?", id))
}

// DeleteBridge removes a bridge.
func (s *Store) DeleteBridge(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM bridges WHERE id=?", id)
	return err
}

// ListBridges returns all bridges.
func (s *Store) ListBridges(ctx context.Context) ([]*Bridge, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+bridgeCols+" FROM bridges ORDER BY to_instance_id, listen_port")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Bridge
	for rows.Next() {
		b, err := scanBridge(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// Bridge modes.
const (
	BridgeHost = "host"
	BridgePort = "port"
)

func (b *Bridge) modeOrDefault() string {
	if b.Mode == "" {
		return BridgePort
	}
	return b.Mode
}

// IsHost reports whether the bridge makes a whole device reachable.
func (b *Bridge) IsHost() bool { return b.Mode == BridgeHost }
