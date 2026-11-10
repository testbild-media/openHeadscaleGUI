//go:build linux

package main

import (
	"fmt"
	"os"
	"syscall"
)

// dropPrivileges switches to the owner of the data directory when a CLI
// command runs as root. Otherwise files created by the CLI (SQLite WAL,
// master key) would be owned by root and unreadable for the service user.
func dropPrivileges(dataDir string) {
	if os.Geteuid() != 0 {
		return
	}
	st, err := os.Stat(dataDir)
	if err != nil {
		return
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys.Uid == 0 {
		return
	}
	if err := syscall.Setgroups([]int{}); err != nil {
		fatal("dropping supplementary groups: %v", err)
	}
	if err := syscall.Setgid(int(sys.Gid)); err != nil {
		fatal("setgid: %v", err)
	}
	if err := syscall.Setuid(int(sys.Uid)); err != nil {
		fatal("setuid: %v", err)
	}
	if os.Geteuid() == 0 {
		fmt.Fprintln(os.Stderr, "ohg: could not drop root privileges")
		os.Exit(1)
	}
}

// refuseRootServe prevents "ohg serve" as root when the data directory
// belongs to the service user (the service must run via systemd).
func refuseRootServe(dataDir string) {
	if os.Geteuid() != 0 {
		return
	}
	if st, err := os.Stat(dataDir); err == nil {
		if sys, ok := st.Sys().(*syscall.Stat_t); ok && sys.Uid != 0 {
			fatal("bitte nicht als root starten – der Dienst läuft über systemd: sudo systemctl start ohg")
		}
	}
}
