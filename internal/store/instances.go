package store

import (
	"context"
	"strings"
)

// Instance is one tailnet served by its own headscale process.
type Instance struct {
	ID               int64
	Slug             string
	Name             string
	OwnerID          int64
	Domain           string
	Enabled          bool
	InternalPort     int
	GatewayPort      int
	PrefixV4         string
	PrefixV6         string
	IPAllocation     string
	MagicDNS         bool
	BaseDomain       string
	Nameservers      string
	OverrideLocalDNS bool
	UseCentralDERP   bool
	UsePublicDERP    bool
	GatewayExitNode  bool
	NodeExpiry       string
	EphemeralTimeout string
	APIKeyEnc        []byte
	CreatedAt        int64
	UpdatedAt        int64
}

// NameserverList returns the configured DNS servers.
func (i *Instance) NameserverList() []string {
	var out []string
	for _, p := range strings.FieldsFunc(i.Nameservers, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

const instanceCols = `id, slug, name, owner_id, domain, enabled, internal_port, gateway_port, prefix_v4, prefix_v6,
	ip_allocation, magic_dns, base_domain, nameservers, override_local_dns, use_central_derp, use_public_derp,
	gateway_exit_node, node_expiry, ephemeral_timeout, api_key_enc, created_at, updated_at`

func scanInstance(row interface{ Scan(...any) error }) (*Instance, error) {
	i := &Instance{}
	var enabled, magic, override, central, public, exit int
	err := row.Scan(&i.ID, &i.Slug, &i.Name, &i.OwnerID, &i.Domain, &enabled, &i.InternalPort, &i.GatewayPort,
		&i.PrefixV4, &i.PrefixV6, &i.IPAllocation, &magic, &i.BaseDomain, &i.Nameservers, &override, &central,
		&public, &exit, &i.NodeExpiry, &i.EphemeralTimeout, &i.APIKeyEnc, &i.CreatedAt, &i.UpdatedAt)
	if err != nil {
		return nil, notFound(err)
	}
	i.Enabled, i.MagicDNS, i.OverrideLocalDNS = enabled == 1, magic == 1, override == 1
	i.UseCentralDERP, i.UsePublicDERP, i.GatewayExitNode = central == 1, public == 1, exit == 1
	return i, nil
}

// CreateInstance inserts an instance.
func (s *Store) CreateInstance(ctx context.Context, i *Instance) error {
	t := now()
	res, err := s.db.ExecContext(ctx, `INSERT INTO instances(slug,name,owner_id,domain,enabled,internal_port,gateway_port,prefix_v4,prefix_v6,
		ip_allocation,magic_dns,base_domain,nameservers,override_local_dns,use_central_derp,use_public_derp,gateway_exit_node,
		node_expiry,ephemeral_timeout,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		i.Slug, i.Name, i.OwnerID, i.Domain, b2i(i.Enabled), i.InternalPort, i.GatewayPort, i.PrefixV4, i.PrefixV6,
		i.IPAllocation, b2i(i.MagicDNS), i.BaseDomain, i.Nameservers, b2i(i.OverrideLocalDNS), b2i(i.UseCentralDERP),
		b2i(i.UsePublicDERP), b2i(i.GatewayExitNode), i.NodeExpiry, i.EphemeralTimeout, t, t)
	if err != nil {
		return err
	}
	i.ID, _ = res.LastInsertId()
	i.CreatedAt, i.UpdatedAt = t, t
	return nil
}

// UpdateInstance stores all mutable fields.
func (s *Store) UpdateInstance(ctx context.Context, i *Instance) error {
	i.UpdatedAt = now()
	_, err := s.db.ExecContext(ctx, `UPDATE instances SET name=?, owner_id=?, domain=?, enabled=?, prefix_v4=?, prefix_v6=?,
		ip_allocation=?, magic_dns=?, base_domain=?, nameservers=?, override_local_dns=?, use_central_derp=?, use_public_derp=?,
		gateway_exit_node=?, node_expiry=?, ephemeral_timeout=?, updated_at=? WHERE id=?`,
		i.Name, i.OwnerID, i.Domain, b2i(i.Enabled), i.PrefixV4, i.PrefixV6, i.IPAllocation, b2i(i.MagicDNS), i.BaseDomain,
		i.Nameservers, b2i(i.OverrideLocalDNS), b2i(i.UseCentralDERP), b2i(i.UsePublicDERP), b2i(i.GatewayExitNode),
		i.NodeExpiry, i.EphemeralTimeout, i.UpdatedAt, i.ID)
	return err
}

// SetInstanceAPIKey stores the encrypted headscale API key.
func (s *Store) SetInstanceAPIKey(ctx context.Context, id int64, enc []byte) error {
	_, err := s.db.ExecContext(ctx, "UPDATE instances SET api_key_enc=? WHERE id=?", enc, id)
	return err
}

// GetInstance returns an instance by ID.
func (s *Store) GetInstance(ctx context.Context, id int64) (*Instance, error) {
	return scanInstance(s.db.QueryRowContext(ctx, "SELECT "+instanceCols+" FROM instances WHERE id=?", id))
}

// GetInstanceBySlug returns an instance by slug.
func (s *Store) GetInstanceBySlug(ctx context.Context, slug string) (*Instance, error) {
	return scanInstance(s.db.QueryRowContext(ctx, "SELECT "+instanceCols+" FROM instances WHERE slug=?", slug))
}

// ListInstances returns all instances, or those of one owner if ownerID > 0.
func (s *Store) ListInstances(ctx context.Context, ownerID int64) ([]*Instance, error) {
	q := "SELECT " + instanceCols + " FROM instances"
	var args []any
	if ownerID > 0 {
		q += " WHERE owner_id=?"
		args = append(args, ownerID)
	}
	q += " ORDER BY name"
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Instance
	for rows.Next() {
		i, err := scanInstance(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// CountInstancesByOwner counts the instances owned by a user.
func (s *Store) CountInstancesByOwner(ctx context.Context, ownerID int64) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM instances WHERE owner_id=?", ownerID).Scan(&n)
	return n, err
}

// DeleteInstance removes an instance and its dependent rows.
func (s *Store) DeleteInstance(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM instances WHERE id=?", id)
	return err
}

// UsedPorts returns all allocated internal and gateway ports.
func (s *Store) UsedPorts(ctx context.Context) (internal, gateway map[int]bool, err error) {
	internal, gateway = map[int]bool{}, map[int]bool{}
	rows, err := s.db.QueryContext(ctx, "SELECT internal_port, gateway_port FROM instances")
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var a, b int
		if err := rows.Scan(&a, &b); err != nil {
			return nil, nil, err
		}
		internal[a], gateway[b] = true, true
	}
	return internal, gateway, rows.Err()
}

// ---- forwards ----

// Forward kinds.
const (
	ForwardHTTP = "http"
	ForwardTCP  = "tcp"
	ForwardUDP  = "udp"
)

// Forward exposes a service inside a tailnet to the internet.
type Forward struct {
	ID               int64
	InstanceID       int64
	Kind             string
	Domain           string
	PublicPort       int
	NodeID           int64
	TargetHost       string
	TargetPort       int
	UpstreamTLS      bool
	UpstreamInsecure bool
	PreserveHost     bool
	AllowCIDRs       string
	BasicAuthUser    string
	BasicAuthHash    string
	Enabled          bool
	Description      string
	CreatedAt        int64
	UpdatedAt        int64
}

const forwardCols = `id, instance_id, kind, COALESCE(domain,''), public_port, node_id, target_host, target_port, upstream_tls,
	upstream_insecure, preserve_host, allow_cidrs, basic_auth_user, basic_auth_hash, enabled, description, created_at, updated_at`

func scanForward(row interface{ Scan(...any) error }) (*Forward, error) {
	f := &Forward{}
	var tls, insecure, preserve, enabled int
	err := row.Scan(&f.ID, &f.InstanceID, &f.Kind, &f.Domain, &f.PublicPort, &f.NodeID, &f.TargetHost, &f.TargetPort,
		&tls, &insecure, &preserve, &f.AllowCIDRs, &f.BasicAuthUser, &f.BasicAuthHash, &enabled, &f.Description, &f.CreatedAt, &f.UpdatedAt)
	if err != nil {
		return nil, notFound(err)
	}
	f.UpstreamTLS, f.UpstreamInsecure, f.PreserveHost, f.Enabled = tls == 1, insecure == 1, preserve == 1, enabled == 1
	return f, nil
}

// CreateForward inserts a forward.
func (s *Store) CreateForward(ctx context.Context, f *Forward) error {
	t := now()
	res, err := s.db.ExecContext(ctx, `INSERT INTO forwards(instance_id,kind,domain,public_port,node_id,target_host,target_port,upstream_tls,
		upstream_insecure,preserve_host,allow_cidrs,basic_auth_user,basic_auth_hash,enabled,description,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		f.InstanceID, f.Kind, nullString(f.Domain), f.PublicPort, f.NodeID, f.TargetHost, f.TargetPort, b2i(f.UpstreamTLS),
		b2i(f.UpstreamInsecure), b2i(f.PreserveHost), f.AllowCIDRs, f.BasicAuthUser, f.BasicAuthHash, b2i(f.Enabled), f.Description, t, t)
	if err != nil {
		return err
	}
	f.ID, _ = res.LastInsertId()
	return nil
}

// UpdateForward stores a forward.
func (s *Store) UpdateForward(ctx context.Context, f *Forward) error {
	_, err := s.db.ExecContext(ctx, `UPDATE forwards SET kind=?, domain=?, public_port=?, node_id=?, target_host=?, target_port=?,
		upstream_tls=?, upstream_insecure=?, preserve_host=?, allow_cidrs=?, basic_auth_user=?, basic_auth_hash=?, enabled=?,
		description=?, updated_at=? WHERE id=?`,
		f.Kind, nullString(f.Domain), f.PublicPort, f.NodeID, f.TargetHost, f.TargetPort, b2i(f.UpstreamTLS), b2i(f.UpstreamInsecure),
		b2i(f.PreserveHost), f.AllowCIDRs, f.BasicAuthUser, f.BasicAuthHash, b2i(f.Enabled), f.Description, now(), f.ID)
	return err
}

// GetForward returns a forward by ID.
func (s *Store) GetForward(ctx context.Context, id int64) (*Forward, error) {
	return scanForward(s.db.QueryRowContext(ctx, "SELECT "+forwardCols+" FROM forwards WHERE id=?", id))
}

// ListForwards returns forwards of one instance (instanceID > 0) or all.
func (s *Store) ListForwards(ctx context.Context, instanceID int64) ([]*Forward, error) {
	q := "SELECT " + forwardCols + " FROM forwards"
	var args []any
	if instanceID > 0 {
		q += " WHERE instance_id=?"
		args = append(args, instanceID)
	}
	q += " ORDER BY kind, domain, public_port"
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Forward
	for rows.Next() {
		f, err := scanForward(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// DeleteForward removes a forward.
func (s *Store) DeleteForward(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM forwards WHERE id=?", id)
	return err
}
