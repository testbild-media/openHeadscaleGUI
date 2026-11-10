// Package headscale talks to and supervises headscale processes.
package headscale

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// U64 is a uint64 that accepts JSON numbers and strings (protojson encodes
// 64 bit integers as strings).
type U64 uint64

// UnmarshalJSON implements json.Unmarshaler.
func (u *U64) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*u = 0
		return nil
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return err
	}
	*u = U64(n)
	return nil
}

// MarshalJSON implements json.Marshaler.
func (u U64) MarshalJSON() ([]byte, error) {
	return []byte(`"` + strconv.FormatUint(uint64(u), 10) + `"`), nil
}

// User is a headscale user (namespace inside a tailnet).
type User struct {
	ID          U64        `json:"id"`
	Name        string     `json:"name"`
	DisplayName string     `json:"displayName"`
	Email       string     `json:"email"`
	Provider    string     `json:"provider"`
	CreatedAt   *time.Time `json:"createdAt"`
}

// PreAuthKey is a headscale pre-authentication key.
type PreAuthKey struct {
	User       *User      `json:"user"`
	ID         U64        `json:"id"`
	Key        string     `json:"key"`
	Reusable   bool       `json:"reusable"`
	Ephemeral  bool       `json:"ephemeral"`
	Used       bool       `json:"used"`
	Expiration *time.Time `json:"expiration"`
	CreatedAt  *time.Time `json:"createdAt"`
	ACLTags    []string   `json:"aclTags"`
}

// Expired reports whether the key can no longer be used.
func (k PreAuthKey) Expired(now time.Time) bool {
	return k.Expiration != nil && !k.Expiration.IsZero() && k.Expiration.Before(now)
}

// Node is a device registered in a tailnet.
type Node struct {
	ID              U64         `json:"id"`
	MachineKey      string      `json:"machineKey"`
	NodeKey         string      `json:"nodeKey"`
	DiscoKey        string      `json:"discoKey"`
	IPAddresses     []string    `json:"ipAddresses"`
	Name            string      `json:"name"`
	User            *User       `json:"user"`
	LastSeen        *time.Time  `json:"lastSeen"`
	Expiry          *time.Time  `json:"expiry"`
	PreAuthKey      *PreAuthKey `json:"preAuthKey"`
	CreatedAt       *time.Time  `json:"createdAt"`
	RegisterMethod  string      `json:"registerMethod"`
	GivenName       string      `json:"givenName"`
	Online          bool        `json:"online"`
	ApprovedRoutes  []string    `json:"approvedRoutes"`
	AvailableRoutes []string    `json:"availableRoutes"`
	SubnetRoutes    []string    `json:"subnetRoutes"`
	Tags            []string    `json:"tags"`
}

// IPv4 returns the node's IPv4 address (or "").
func (n Node) IPv4() string {
	for _, ip := range n.IPAddresses {
		if strings.Contains(ip, ".") {
			return ip
		}
	}
	return ""
}

// IPv6 returns the node's IPv6 address (or "").
func (n Node) IPv6() string {
	for _, ip := range n.IPAddresses {
		if strings.Contains(ip, ":") {
			return ip
		}
	}
	return ""
}

// UserName returns the owning user name ("" for tagged nodes).
func (n Node) UserName() string {
	if n.User == nil {
		return ""
	}
	return n.User.Name
}

// Expired reports whether the node key expired.
func (n Node) Expired(now time.Time) bool {
	return n.Expiry != nil && !n.Expiry.IsZero() && n.Expiry.Year() > 1 && n.Expiry.Before(now)
}

// DisplayName returns the best name for display.
func (n Node) DisplayName() string {
	if n.GivenName != "" {
		return n.GivenName
	}
	return n.Name
}

// APIError is an error returned by the headscale API.
type APIError struct {
	Status  int
	Code    int
	Message string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("headscale: %s", e.Message)
	}
	return fmt.Sprintf("headscale: HTTP %d", e.Status)
}

// IsUnauthorized reports whether err is an authentication failure.
func IsUnauthorized(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == http.StatusUnauthorized
}

// IsNotFound reports whether err is a not-found error.
func IsNotFound(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && (ae.Status == http.StatusNotFound || ae.Code == 5)
}

// Client is a REST client for the headscale API.
type Client struct {
	base string
	key  string
	http *http.Client
}

// NewClient creates a client for baseURL (e.g. http://127.0.0.1:42000).
func NewClient(baseURL, apiKey string) *Client {
	return &Client{
		base: strings.TrimRight(baseURL, "/"),
		key:  apiKey,
		http: &http.Client{Timeout: 20 * time.Second},
	}
}

func (c *Client) do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	u := c.base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.key)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 32<<20))
	if err != nil {
		return err
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		ae := &APIError{Status: res.StatusCode}
		var e struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}
		if json.Unmarshal(data, &e) == nil {
			ae.Code, ae.Message = e.Code, e.Message
		} else {
			ae.Message = strings.TrimSpace(string(data))
			if len(ae.Message) > 300 {
				ae.Message = ae.Message[:300]
			}
		}
		return ae
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decoding headscale response: %w", err)
		}
	}
	return nil
}

func idPath(id uint64) string { return strconv.FormatUint(id, 10) }

// Health checks API reachability and authentication.
func (c *Client) Health(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/api/v1/apikey", nil, nil, nil)
}

// ---- nodes ----

// ListNodes returns all nodes.
func (c *Client) ListNodes(ctx context.Context) ([]Node, error) {
	var out struct {
		Nodes []Node `json:"nodes"`
	}
	err := c.do(ctx, http.MethodGet, "/api/v1/node", nil, nil, &out)
	return out.Nodes, err
}

// GetNode returns a node.
func (c *Client) GetNode(ctx context.Context, id uint64) (*Node, error) {
	var out struct {
		Node *Node `json:"node"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v1/node/"+idPath(id), nil, nil, &out); err != nil {
		return nil, err
	}
	if out.Node == nil {
		return nil, &APIError{Status: 404, Message: "node not found"}
	}
	return out.Node, nil
}

// DeleteNode removes a node.
func (c *Client) DeleteNode(ctx context.Context, id uint64) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/node/"+idPath(id), nil, nil, nil)
}

// RenameNode sets the node's given name.
func (c *Client) RenameNode(ctx context.Context, id uint64, name string) error {
	return c.do(ctx, http.MethodPost, "/api/v1/node/"+idPath(id)+"/rename/"+url.PathEscape(name), nil, nil, nil)
}

// ExpireNode expires a node key now (forces re-authentication).
func (c *Client) ExpireNode(ctx context.Context, id uint64) error {
	return c.do(ctx, http.MethodPost, "/api/v1/node/"+idPath(id)+"/expire", nil, nil, nil)
}

// DisableNodeExpiry makes a node key never expire.
func (c *Client) DisableNodeExpiry(ctx context.Context, id uint64) error {
	q := url.Values{"disableExpiry": {"true"}}
	return c.do(ctx, http.MethodPost, "/api/v1/node/"+idPath(id)+"/expire", q, nil, nil)
}

// SetNodeExpiry sets the expiry of a node key.
func (c *Client) SetNodeExpiry(ctx context.Context, id uint64, t time.Time) error {
	q := url.Values{"expiry": {t.UTC().Format(time.RFC3339)}}
	return c.do(ctx, http.MethodPost, "/api/v1/node/"+idPath(id)+"/expire", q, nil, nil)
}

// SetApprovedRoutes replaces the approved routes of a node.
func (c *Client) SetApprovedRoutes(ctx context.Context, id uint64, routes []string) error {
	if routes == nil {
		routes = []string{}
	}
	return c.do(ctx, http.MethodPost, "/api/v1/node/"+idPath(id)+"/approve_routes", nil, map[string]any{"routes": routes}, nil)
}

// SetTags replaces the tags of a node.
func (c *Client) SetTags(ctx context.Context, id uint64, tags []string) error {
	if tags == nil {
		tags = []string{}
	}
	return c.do(ctx, http.MethodPost, "/api/v1/node/"+idPath(id)+"/tags", nil, map[string]any{"tags": tags}, nil)
}

// AuthRegister completes an interactive registration for user (name).
func (c *Client) AuthRegister(ctx context.Context, user, authID string) (*Node, error) {
	var out struct {
		Node *Node `json:"node"`
	}
	err := c.do(ctx, http.MethodPost, "/api/v1/auth/register", nil, map[string]any{"user": user, "authId": authID}, &out)
	return out.Node, err
}

// AuthReject rejects a pending interactive registration.
func (c *Client) AuthReject(ctx context.Context, authID string) error {
	return c.do(ctx, http.MethodPost, "/api/v1/auth/reject", nil, map[string]any{"authId": authID}, nil)
}

// ---- users ----

// ListUsers returns all users.
func (c *Client) ListUsers(ctx context.Context) ([]User, error) {
	var out struct {
		Users []User `json:"users"`
	}
	err := c.do(ctx, http.MethodGet, "/api/v1/user", nil, nil, &out)
	return out.Users, err
}

// CreateUser creates a user.
func (c *Client) CreateUser(ctx context.Context, name, displayName string) (*User, error) {
	var out struct {
		User *User `json:"user"`
	}
	err := c.do(ctx, http.MethodPost, "/api/v1/user", nil, map[string]any{"name": name, "displayName": displayName}, &out)
	return out.User, err
}

// RenameUser renames a user.
func (c *Client) RenameUser(ctx context.Context, id uint64, newName string) error {
	return c.do(ctx, http.MethodPost, "/api/v1/user/"+idPath(id)+"/rename/"+url.PathEscape(newName), nil, nil, nil)
}

// DeleteUser deletes a user.
func (c *Client) DeleteUser(ctx context.Context, id uint64) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/user/"+idPath(id), nil, nil, nil)
}

// ---- pre-auth keys ----

// ListPreAuthKeys returns all pre-auth keys.
func (c *Client) ListPreAuthKeys(ctx context.Context) ([]PreAuthKey, error) {
	var out struct {
		Keys []PreAuthKey `json:"preAuthKeys"`
	}
	err := c.do(ctx, http.MethodGet, "/api/v1/preauthkey", nil, nil, &out)
	return out.Keys, err
}

// CreatePreAuthKeyRequest holds the options for a new key.
type CreatePreAuthKeyRequest struct {
	UserID     uint64
	Reusable   bool
	Ephemeral  bool
	Expiration time.Time
	Tags       []string
}

// CreatePreAuthKey creates a key.
func (c *Client) CreatePreAuthKey(ctx context.Context, r CreatePreAuthKeyRequest) (*PreAuthKey, error) {
	body := map[string]any{
		"reusable":   r.Reusable,
		"ephemeral":  r.Ephemeral,
		"expiration": r.Expiration.UTC().Format(time.RFC3339),
	}
	if r.UserID != 0 {
		body["user"] = strconv.FormatUint(r.UserID, 10)
	}
	if len(r.Tags) > 0 {
		body["aclTags"] = r.Tags
	}
	var out struct {
		Key *PreAuthKey `json:"preAuthKey"`
	}
	err := c.do(ctx, http.MethodPost, "/api/v1/preauthkey", nil, body, &out)
	if err == nil && out.Key == nil {
		err = errors.New("headscale returned no key")
	}
	return out.Key, err
}

// ExpirePreAuthKey expires a key.
func (c *Client) ExpirePreAuthKey(ctx context.Context, id uint64) error {
	return c.do(ctx, http.MethodPost, "/api/v1/preauthkey/expire", nil, map[string]any{"id": strconv.FormatUint(id, 10)}, nil)
}

// DeletePreAuthKey deletes a key.
func (c *Client) DeletePreAuthKey(ctx context.Context, id uint64) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/preauthkey", url.Values{"id": {strconv.FormatUint(id, 10)}}, nil, nil)
}

// ---- policy ----

// GetPolicy returns the stored ACL policy (HuJSON) or "".
func (c *Client) GetPolicy(ctx context.Context) (string, error) {
	var out struct {
		Policy string `json:"policy"`
	}
	err := c.do(ctx, http.MethodGet, "/api/v1/policy", nil, nil, &out)
	if err != nil {
		var ae *APIError
		if errors.As(err, &ae) && (ae.Status == 404 || ae.Status == 500 && strings.Contains(strings.ToLower(ae.Message), "not found")) {
			return "", nil
		}
	}
	return out.Policy, err
}

// SetPolicy stores the ACL policy.
func (c *Client) SetPolicy(ctx context.Context, policy string) error {
	return c.do(ctx, http.MethodPut, "/api/v1/policy", nil, map[string]any{"policy": policy}, nil)
}

// CheckPolicy validates a policy without storing it.
func (c *Client) CheckPolicy(ctx context.Context, policy string) error {
	return c.do(ctx, http.MethodPost, "/api/v1/policy/check", nil, map[string]any{"policy": policy}, nil)
}
