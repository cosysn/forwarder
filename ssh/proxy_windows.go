//go:build windows
// +build windows

package ssh

import (
	"fmt"
	"log"
	"os/exec"

	"golang.org/x/sys/windows"
)

// sshProxyCommand creates a connection using the given ProxyCommand string
func sshProxyCommand(command string) (*proxyCmdConn, error) {
	var cmd *exec.Cmd

	// Parse Windows command properly - extract exe and arguments
	args := parseWindowsCommand(command)
	if len(args) < 1 {
		return nil, fmt.Errorf("empty command")
	}
	exe := args[0]
	restArgs := []string{}
	if len(args) > 1 {
		restArgs = args[1:]
	}
	log.Printf("Windows: exe=%s args=%v", exe, restArgs)
	cmd = exec.Command(exe, restArgs...)
	cmd.SysProcAttr = &windows.SysProcAttr{
		CreationFlags: windows.CREATE_NEW_CONSOLE,
	}

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
