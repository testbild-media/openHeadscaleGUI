//go:build linux

package headscale

import "syscall"

// sysProcAttr puts children in their own process group. Pdeathsig is not
// used on purpose: it fires when the spawning OS thread exits, which the Go
// runtime may do at any time. systemd (KillMode=control-group) cleans up
// children when ohg stops.
func sysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}
