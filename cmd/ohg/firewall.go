package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/testbild-media/openHeadscaleGUI/internal/fwsync"
)

// firewallSync applies the ports of the TCP/UDP forwards to UFW/firewalld.
// It runs as root via systemd (ohg-firewall.service, started by
// ohg-firewall.path when ohg changes its port list and by
// ohg-firewall.timer every few minutes). ohg itself stays unprivileged.
func firewallSync(args []string) {
	if os.Geteuid() != 0 {
		fatal("firewall-sync muss als root laufen (systemd: ohg-firewall.service)")
	}
	removeAll := len(args) > 0 && args[0] == "--remove-all" // uninstall
	cfg := loadConfig()
	st := fwsync.Sync(fwsync.Options{DataDir: cfg.DataDir, RemoveAll: removeAll})
	fmt.Printf("firewall: %s\n", st.Backend)
	for _, p := range st.Ports {
		fmt.Println(strings.TrimSpace(fmt.Sprintf("%s %s %s", p.Key(), p.State, p.Detail)))
	}
	for _, p := range st.Removed {
		fmt.Printf("%s removed\n", p.Key())
	}
	if st.Error != "" {
		fatal("%s", st.Error)
	}
}
