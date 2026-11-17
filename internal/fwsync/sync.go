package fwsync

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Options of a sync run. Zero values are filled with the real system
// (tests replace them).
type Options struct {
	DataDir  string // ohg's data directory (owner = ohg user)
	StateDir string // root-owned, default DefaultStateDir
	// Run executes a command and returns its combined output.
	Run func(name string, args ...string) (string, error)
	// Have reports whether a command exists.
	Have func(name string) bool
	// OwnerUID returns the owner of a path (the ohg user).
	OwnerUID func(path string) (int, error)
	// ReadDesired reads the wanted ports, refusing files not owned by uid.
	ReadDesired func(path string, uid int) ([]Port, error)
	// Listening returns the ports ("25565/tcp") a uid listens on.
	Listening func(uid int) (map[string]bool, error)
	Now       func() time.Time
	Sleep     func(time.Duration)
	// RemoveAll removes every rule the sync created (uninstall).
	RemoveAll bool
}

func (o *Options) defaults() {
	if o.StateDir == "" {
		o.StateDir = DefaultStateDir
	}
	if o.Run == nil {
		o.Run = func(name string, args ...string) (string, error) {
			out, err := exec.Command(name, args...).CombinedOutput()
			return string(out), err
		}
	}
	if o.Have == nil {
		o.Have = func(name string) bool { _, err := exec.LookPath(name); return err == nil }
	}
	if o.OwnerUID == nil {
		o.OwnerUID = ownerUID
	}
	if o.ReadDesired == nil {
		o.ReadDesired = readDesiredSecure
	}
	if o.Listening == nil {
		o.Listening = func(uid int) (map[string]bool, error) { return ListeningPorts("/proc/net", uid) }
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Sleep == nil {
		o.Sleep = time.Sleep
	}
}

// Sync applies the wanted ports to the firewall and writes the status.
func Sync(o Options) *Status {
	o.defaults()
	st := run(&o)
	st.Updated = o.Now()
	if err := os.MkdirAll(o.StateDir, 0o755); err == nil {
		if data, err := json.MarshalIndent(st, "", "  "); err == nil {
			if err := writeAtomic(StatusFile(o.StateDir), data, 0o644); err != nil && st.Error == "" {
				st.Error = "Status nicht geschrieben: " + err.Error()
			}
		}
	}
	return st
}

func run(o *Options) *Status {
	st := &Status{Backend: "none"}
	uid, err := o.OwnerUID(o.DataDir)
	if err != nil {
		st.Error = "Datenverzeichnis: " + err.Error()
		return st
	}
	if uid == 0 {
		st.Error = "Das Datenverzeichnis gehört root – ohg muss als eigener Benutzer laufen"
		return st
	}
	var desired []Port
	if !o.RemoveAll {
		if desired, err = o.ReadDesired(DesiredFile(o.DataDir), uid); err != nil {
			st.Error = "Portliste: " + err.Error()
			return st
		}
	}

	// Validate and check that ohg really listens on each port. The
	// listeners start asynchronously, so wait a little for missing ones.
	valid := []Port{}
	for _, p := range desired {
		switch {
		case p.Proto != "tcp" && p.Proto != "udp":
			st.Ports = append(st.Ports, PortStatus{Port: p, State: StateRefused, Detail: "unbekanntes Protokoll"})
		case p.Port < MinPort || p.Port > 65535:
			st.Ports = append(st.Ports, PortStatus{Port: p, State: StateRefused, Detail: "Ports unter 1024 öffnet ohg nie"})
		default:
			valid = append(valid, p)
		}
	}
	var listening map[string]bool
	for attempt := 0; attempt < 4; attempt++ {
		if listening, err = o.Listening(uid); err != nil {
			st.Error = "Offene Ports nicht lesbar: " + err.Error()
			return st
		}
		if len(listening) == 0 && !o.RemoveAll {
			// ohg always listens on its own ports while it runs: it is
			// stopped or restarting – leave the rules alone until it is
			// back (it triggers a sync after every start)
			st.Error = "ohg läuft nicht – Freigaben unverändert"
			return st
		}
		missing := false
		for _, p := range valid {
			if !listening[p.Key()] {
				missing = true
			}
		}
		if !missing {
			break
		}
		o.Sleep(time.Second)
	}
	want := map[string]Port{}
	var order []string
	for _, p := range valid {
		if !listening[p.Key()] {
			st.Ports = append(st.Ports, PortStatus{Port: p, State: StateNotListening,
				Detail: "ohg lauscht nicht auf diesem Port (belegt oder Forward startet gerade)"})
			continue
		}
		if _, dup := want[p.Key()]; !dup {
			order = append(order, p.Key())
		}
		want[p.Key()] = p
	}

	switch {
	case o.Have("ufw") && ufwActive(o):
		st.Backend = "ufw"
		syncUFW(o, st, want, order)
	case o.Have("firewall-cmd") && firewalldRunning(o):
		st.Backend = "firewalld"
		syncFirewalld(o, st, want, order)
	default:
		for _, k := range order {
			st.Ports = append(st.Ports, PortStatus{Port: want[k], State: StateNoFirewall})
		}
	}
	sortStatus(st.Ports)
	return st
}

func sortStatus(ps []PortStatus) {
	ports := make([]Port, len(ps))
	idx := map[string]PortStatus{}
	for i, p := range ps {
		ports[i] = p.Port
		idx[p.Key()+"|"+p.Name] = p
	}
	sortPorts(ports)
	for i, p := range ports {
		ps[i] = idx[p.Key()+"|"+p.Name]
	}
}

// ---- UFW ----

func ufwActive(o *Options) bool {
	out, err := o.Run("ufw", "status")
	return err == nil && strings.Contains(out, "Status: active")
}

// ufwRule is one line of "ufw status".
type ufwRule struct {
	from, to   int    // port range
	proto      string // "" = both
	allowAll   bool   // ALLOW from Anywhere
	ours       bool   // comment == Marker
	isPortRule bool
}

// parseUFWStatus reads the rules of "ufw status".
func parseUFWStatus(out string) []ufwRule {
	var rules []ufwRule
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		comment := ""
		if i := strings.Index(line, "# "); i >= 0 {
			comment = strings.TrimSpace(line[i+2:])
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		r := ufwRule{ours: comment == Marker}
		spec := f[0]
		if i := strings.IndexByte(spec, '/'); i >= 0 {
			r.proto, spec = spec[i+1:], spec[:i]
		}
		lo, hi, ok := parsePortSpec(spec)
		if !ok {
			continue
		}
		r.from, r.to, r.isPortRule = lo, hi, true
		// action is the first field starting with ALLOW/DENY/REJECT/LIMIT
		rest := f[1:]
		if len(rest) > 0 && rest[0] == "(v6)" {
			rest = rest[1:]
		}
		if len(rest) < 2 {
			continue
		}
		action := rest[0]
		from := strings.Join(rest[1:], " ")
		if rest[1] == "IN" { // "ALLOW IN"
			from = strings.Join(rest[2:], " ")
		}
		r.allowAll = action == "ALLOW" && strings.HasPrefix(from, "Anywhere")
		rules = append(rules, r)
	}
	return rules
}

func parsePortSpec(s string) (int, int, bool) {
	if a, b, ok := strings.Cut(s, ":"); ok {
		lo, err1 := strconv.Atoi(a)
		hi, err2 := strconv.Atoi(b)
		return lo, hi, err1 == nil && err2 == nil && lo <= hi
	}
	p, err := strconv.Atoi(s)
	return p, p, err == nil
}

func (r ufwRule) covers(p Port) bool {
	return r.isPortRule && p.Port >= r.from && p.Port <= r.to && (r.proto == "" || r.proto == p.Proto)
}

func syncUFW(o *Options, st *Status, want map[string]Port, order []string) {
	out, err := o.Run("ufw", "status")
	if err != nil {
		st.Error = "ufw status: " + strings.TrimSpace(out)
		return
	}
	rules := parseUFWStatus(out)
	ours := map[string]Port{}
	for _, r := range rules {
		if r.ours && r.from == r.to && r.proto != "" {
			p := Port{Port: r.from, Proto: r.proto}
			ours[p.Key()] = p
		}
	}
	for _, k := range order {
		p := want[k]
		if _, ok := ours[k]; ok {
			st.Ports = append(st.Ports, PortStatus{Port: p, State: StateOpened})
			continue
		}
		// a rule of the administrator already allows the port: leave it
		// alone (adding ours would rewrite its comment, and deleting ours
		// later would delete the administrator's rule)
		existing, foreign := false, false
		for _, r := range rules {
			if r.ours || !r.covers(p) {
				continue
			}
			if r.allowAll {
				existing = true
			} else {
				foreign = true // e.g. only from certain networks, or denied
			}
		}
		if existing {
			st.Ports = append(st.Ports, PortStatus{Port: p, State: StateExisting})
			continue
		}
		if foreign {
			st.Ports = append(st.Ports, PortStatus{Port: p, State: StateForeign,
				Detail: "eigene UFW-Regel für diesen Port (eingeschränkt oder gesperrt) – ohg ändert nichts"})
			continue
		}
		res, err := o.Run("ufw", "allow", p.Key(), "comment", Marker)
		switch {
		case err != nil:
			st.Ports = append(st.Ports, PortStatus{Port: p, State: StateError, Detail: firstLine(res)})
		case strings.Contains(res, "Skipping"):
			st.Ports = append(st.Ports, PortStatus{Port: p, State: StateExisting})
		default:
			st.Ports = append(st.Ports, PortStatus{Port: p, State: StateOpened})
		}
	}
	for k, p := range ours {
		if _, ok := want[k]; ok {
			continue
		}
		if res, err := o.Run("ufw", "delete", "allow", k); err != nil {
			st.Error = "ufw delete " + k + ": " + firstLine(res)
			continue
		}
		st.Removed = append(st.Removed, p)
	}
	sortPorts(st.Removed)
}

// ---- firewalld ----

func firewalldRunning(o *Options) bool {
	out, err := o.Run("firewall-cmd", "--state")
	return err == nil && strings.TrimSpace(out) == "running"
}

// stateFile lists the firewalld ports the sync opened itself.
func stateFile(dir string) string { return filepath.Join(dir, "firewalld-ports.json") }

func loadOwned(dir string) map[string]Port {
	m := map[string]Port{}
	if data, err := os.ReadFile(stateFile(dir)); err == nil {
		var ports []Port
		if json.Unmarshal(data, &ports) == nil {
			for _, p := range ports {
				m[p.Key()] = p
			}
		}
	}
	return m
}

func saveOwned(dir string, m map[string]Port) error {
	ports := make([]Port, 0, len(m))
	for _, p := range m {
		ports = append(ports, Port{Port: p.Port, Proto: p.Proto})
	}
	sortPorts(ports)
	data, _ := json.MarshalIndent(ports, "", "  ")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return writeAtomic(stateFile(dir), data, 0o644)
}

func syncFirewalld(o *Options, st *Status, want map[string]Port, order []string) {
	owned := loadOwned(o.StateDir)
	for _, k := range order {
		p := want[k]
		if _, ok := owned[k]; ok {
			// ours: make sure it is still there (e.g. after a reload)
			if _, err := o.Run("firewall-cmd", "--query-port="+k); err != nil {
				o.Run("firewall-cmd", "--add-port="+k)
			}
			if _, err := o.Run("firewall-cmd", "--permanent", "--query-port="+k); err != nil {
				o.Run("firewall-cmd", "--permanent", "--add-port="+k)
			}
			st.Ports = append(st.Ports, PortStatus{Port: p, State: StateOpened})
			continue
		}
		if _, err := o.Run("firewall-cmd", "--query-port="+k); err == nil {
			st.Ports = append(st.Ports, PortStatus{Port: p, State: StateExisting})
			continue
		}
		if res, err := o.Run("firewall-cmd", "--add-port="+k); err != nil {
			st.Ports = append(st.Ports, PortStatus{Port: p, State: StateError, Detail: firstLine(res)})
			continue
		}
		if res, err := o.Run("firewall-cmd", "--permanent", "--add-port="+k); err != nil {
			st.Ports = append(st.Ports, PortStatus{Port: p, State: StateError, Detail: "dauerhaft: " + firstLine(res)})
		}
		owned[k] = p
		st.Ports = append(st.Ports, PortStatus{Port: p, State: StateOpened})
	}
	for k, p := range owned {
		if _, ok := want[k]; ok {
			continue
		}
		o.Run("firewall-cmd", "--remove-port="+k)
		o.Run("firewall-cmd", "--permanent", "--remove-port="+k)
		delete(owned, k)
		st.Removed = append(st.Removed, p)
	}
	sortPorts(st.Removed)
	if err := saveOwned(o.StateDir, owned); err != nil && st.Error == "" {
		st.Error = "Zustand nicht gespeichert: " + err.Error()
	}
}

// ---- listening sockets ----

// ListeningPorts parses /proc/net/{tcp,tcp6,udp,udp6} and returns the
// ports ("25565/tcp") on which sockets of uid listen.
func ListeningPorts(procNet string, uid int) (map[string]bool, error) {
	out := map[string]bool{}
	found := false
	for _, f := range []struct{ file, proto, state string }{
		{"tcp", "tcp", "0A"}, {"tcp6", "tcp", "0A"}, {"udp", "udp", "07"}, {"udp6", "udp", "07"},
	} {
		data, err := os.ReadFile(filepath.Join(procNet, f.file))
		if err != nil {
			continue
		}
		found = true
		parseProcNet(string(data), f.proto, f.state, uid, out)
	}
	if !found {
		return nil, errors.New("keine Socket-Tabellen unter " + procNet)
	}
	return out, nil
}

func parseProcNet(data, proto, wantState string, uid int, out map[string]bool) {
	lines := strings.Split(data, "\n")
	for _, line := range lines[min(1, len(lines)):] {
		f := strings.Fields(line)
		if len(f) < 8 || f[3] != wantState {
			continue
		}
		if u, err := strconv.Atoi(f[7]); err != nil || u != uid {
			continue
		}
		_, portHex, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		port, err := strconv.ParseUint(portHex, 16, 16)
		if err != nil {
			continue
		}
		out[fmt.Sprintf("%d/%s", port, proto)] = true
	}
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
