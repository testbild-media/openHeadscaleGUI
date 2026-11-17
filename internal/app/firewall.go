package app

import (
	"os"
	"strconv"
	"time"

	"github.com/testbild-media/openHeadscaleGUI/internal/forward"
	"github.com/testbild-media/openHeadscaleGUI/internal/fwsync"
)

// FirewallStatusFile is written by "ohg firewall-sync" (root, see
// package fwsync); ohg only reads it.
var FirewallStatusFile = fwsync.StatusFile(fwsync.DefaultStateDir)

// firewallStale: after this long without a sync run for a changed port
// list the GUI reports that the automation does not react.
const firewallStale = 3 * time.Minute

// writeFirewallPorts hands the ports of the active TCP/UDP forwards to the
// root firewall sync.
func (a *App) writeFirewallPorts(rules []forward.Rule) {
	ports := make([]fwsync.Port, 0, len(rules))
	for _, r := range rules {
		ports = append(ports, fwsync.Port{Port: r.Port, Proto: r.Proto, Name: "forward " + strconv.FormatInt(r.ID, 10)})
	}
	// the first write after a start always touches the file: the sync then
	// runs once the listeners are up again
	force := !a.fwWritten.Swap(true)
	if err := fwsync.WriteDesired(a.Cfg.DataDir, ports, force); err != nil {
		a.Log.Warn("writing the firewall port list failed", "err", err)
	}
}

// FirewallView is the state of the host firewall automation for the GUI.
type FirewallView struct {
	// Installed: the sync ran at least once (status file present).
	Installed bool
	// Pending: the port list changed after the last run; Stale: and the
	// sync has not reacted for minutes (units not active?).
	Pending, Stale bool
	Backend        string
	Updated        time.Time
	Error          string
	status         *fwsync.Status
}

// Port returns the result for a forward port ("" state = unknown yet).
func (v FirewallView) Port(port int, proto string) fwsync.PortStatus {
	return v.status.Lookup(fwsync.Port{Port: port, Proto: proto}.Key())
}

// FirewallView reads the status of the firewall sync.
func (a *App) FirewallView() FirewallView {
	st, err := fwsync.ReadStatus(FirewallStatusFile)
	if err != nil {
		return FirewallView{Installed: true, Error: "Status nicht lesbar: " + err.Error()}
	}
	if st == nil {
		return FirewallView{}
	}
	v := FirewallView{Installed: true, Backend: st.Backend, Updated: st.Updated, Error: st.Error, status: st}
	if fi, err := os.Stat(fwsync.DesiredFile(a.Cfg.DataDir)); err == nil && fi.ModTime().After(st.Updated) {
		v.Pending = true
		v.Stale = time.Since(fi.ModTime()) > firewallStale
	}
	return v
}
