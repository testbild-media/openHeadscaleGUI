//go:build !windows

package headscale

import (
	"os/exec"
	"syscall"
)

func setProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = sysProcAttr()
}

func terminate(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Signal(syscall.SIGTERM)
	}
}

// perRunConfig returns nil: the config is used unchanged.
func perRunConfig(cfg []byte) []byte { return nil }
