//go:build !windows

package ssh

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

type Client struct {
	cmd        *exec.Cmd
	socketPath string
}

func NewClient(remoteHost string, remotePort, localPort int, username, password string) (*Client, error) {
	// Create socket directory
	socketDir := filepath.Join(os.TempDir(), "ssh-forwarder")
	os.MkdirAll(socketDir, 0700)
	socketPath := filepath.Join(socketDir, fmt.Sprintf("%s_%d",
		strings.ReplaceAll(remoteHost, ":", "_"),
		remotePort))

	// Build ssh command with ControlMaster for multiplexing
	args := []string{
		"-N",                    // Don't execute remote command
		"-M",                    // Master mode for multiplexing
		"-o", "ControlMaster=auto",
		"-o", fmt.Sprintf("ControlPath=%s", socketPath),
		"-o", "ControlPersist=600", // Persist master connection for 600s after close
		"-o", "StrictHostKeyChecking=no",
		"-o", "ServerAliveInterval=60",
		"-o", "ServerAliveCountMax=3",
	}

	// Add username if provided
	if username != "" {
		args = append(args, "-l", username)
	}

	// Build remote address
	addr := remoteHost
	if remotePort != 0 && remotePort != 22 {
		addr = fmt.Sprintf("%s:%d", remoteHost, remotePort)
	}
	args = append(args, addr)

	log.Printf("Starting SSH master connection to %s", addr)

	cmd := exec.Command("ssh", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Setpgid only works on Unix
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
		Pgid: 0,
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start SSH: %v", err)
	}

	// Wait for socket to be created
	for i := 0; i < 30; i++ {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		log.Printf("Waiting for SSH master connection...")
	}

	log.Println("SSH master connection established")

	return &Client{
		cmd:        cmd,
		socketPath: socketPath,
	}, nil
}

func (c *Client) GetSocketPath() string {
	return c.socketPath
}

func (c *Client) Close() {
	if c.cmd != nil {
		c.cmd.Process.Kill()
		c.cmd.Wait()
	}
	// Clean up socket
	os.Remove(c.socketPath)
	log.Println("SSH connection closed")
}
