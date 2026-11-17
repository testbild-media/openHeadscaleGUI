// Package fwsync opens the host firewall (UFW or firewalld) for the TCP/UDP
// port forwards of ohg.
//
// ohg itself runs unprivileged and may not touch the firewall. It only
// writes the list of wanted ports (DesiredFile). "ohg firewall-sync", run as
// root by systemd (ohg-firewall.path/.timer), applies the list:
//
//   - a port is only opened while a process of the ohg user listens on it,
//     so a compromised ohg cannot expose other services of the host;
//   - ports below 1024 are never touched;
//   - only rules created by the sync itself are removed again – rules of
//     the administrator stay as they are.
package fwsync

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Marker is the UFW rule comment of rules created by the sync.
const Marker = "ohg-forward"

// DefaultStateDir holds the root-owned status and state of the sync.
const DefaultStateDir = "/var/lib/ohg-firewall"

const (
	maxDesiredSize = 256 << 10
	maxPorts       = 2000
	// MinPort: ports below are never opened (system services, ohg's own
	// base ports are opened by the installer).
	MinPort = 1024
)

// Port is a port a forward listens on.
type Port struct {
	Port  int    `json:"port"`
	Proto string `json:"proto"` // tcp | udp
	Name  string `json:"name,omitempty"`
}

// Key identifies the port, e.g. "25565/tcp".
func (p Port) Key() string { return fmt.Sprintf("%d/%s", p.Port, p.Proto) }

// Desired is the file ohg writes.
type Desired struct {
	Ports []Port `json:"ports"`
}

// Port states reported by the sync.
const (
	StateOpened       = "opened"        // rule created by the sync
	StateExisting     = "existing"      // already allowed by a rule of the administrator
	StateForeign      = "foreign"       // the administrator restricts the port with own rules: left alone
	StateNoFirewall   = "no-firewall"   // neither UFW nor firewalld active: nothing to open
	StateNotListening = "not-listening" // ohg does not listen on the port (yet)
	StateRefused      = "refused"       // never handled (port < 1024, bad protocol)
	StateError        = "error"
)

// PortStatus is the result for one port.
type PortStatus struct {
	Port
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
}

// Status is written by the sync after every run.
type Status struct {
	Backend string       `json:"backend"` // ufw | firewalld | none
	Updated time.Time    `json:"updated"`
	Ports   []PortStatus `json:"ports"`
	Removed []Port       `json:"removed,omitempty"`
	Error   string       `json:"error,omitempty"`
}

// Lookup returns the status of a port ("" state when unknown).
func (s *Status) Lookup(key string) PortStatus {
	if s != nil {
		for _, p := range s.Ports {
			if p.Key() == key {
				return p
			}
		}
	}
	return PortStatus{}
}

// DesiredFile is the list of wanted ports inside ohg's data directory.
func DesiredFile(dataDir string) string { return filepath.Join(dataDir, "firewall", "ports.json") }

// StatusFile is the status written by the sync.
func StatusFile(stateDir string) string { return filepath.Join(stateDir, "status.json") }

func sortPorts(ports []Port) {
	sort.Slice(ports, func(i, j int) bool {
		if ports[i].Port != ports[j].Port {
			return ports[i].Port < ports[j].Port
		}
		return ports[i].Proto < ports[j].Proto
	})
}

// WriteDesired writes the wanted ports (ohg side). The file is only
// replaced when its content changes (or force is set, after a start of
// ohg): the systemd path unit starts the sync on every change.
func WriteDesired(dataDir string, ports []Port, force bool) error {
	ports = append([]Port(nil), ports...)
	sortPorts(ports)
	if ports == nil {
		ports = []Port{}
	}
	data, err := json.MarshalIndent(Desired{Ports: ports}, "", "  ")
	if err != nil {
		return err
	}
	path := DesiredFile(dataDir)
	if cur, err := os.ReadFile(path); err == nil && bytes.Equal(cur, data) && !force {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return writeAtomic(path, data, 0o640)
}

// ReadStatus reads the status of the last sync (nil, nil when the sync
// never ran, i.e. it is not installed).
func ReadStatus(path string) (*Status, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s Status
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
