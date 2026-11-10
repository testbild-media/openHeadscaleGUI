//go:build windows

package headscale

import "os/exec"

// Windows is only supported for local development.
func setProcAttr(cmd *exec.Cmd) {}

func terminate(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
