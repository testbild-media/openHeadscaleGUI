//go:build windows

package headscale

import (
	"bytes"
	"fmt"
	"os/exec"
	"time"
)

// Windows is only supported for local development.
func setProcAttr(cmd *exec.Cmd) {}

func terminate(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}

// perRunConfig gives every headscale start a fresh unix socket name: stale
// AF_UNIX socket files of killed processes cannot be removed on Windows.
func perRunConfig(cfg []byte) []byte {
	name := fmt.Sprintf("headscale-%d.sock", time.Now().UnixNano())
	return bytes.Replace(cfg, []byte("unix_socket: headscale.sock"), []byte("unix_socket: "+name), 1)
}
