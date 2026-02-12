//go:build !windows
// +build !windows

package ssh

import (
	"fmt"
	"log"
	"os/exec"
)

// sshProxyCommand creates a connection using the given ProxyCommand string
func sshProxyCommand(command string) (*proxyCmdConn, error) {
	cmd := exec.Command("sh", "-c", command)

	log.Printf("ProxyCommand: %s", command)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("stdin pipe: %v", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start command: %v", err)
	}

	log.Printf("ProxyCommand started (PID: %d)", cmd.Process.Pid)

	return newProxyCmdConn(cmd, stdin, stdout), nil
}
