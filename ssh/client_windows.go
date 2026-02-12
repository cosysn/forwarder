//go:build windows

package ssh

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type Client struct {
	cmd        *exec.Cmd
	socketPath string
}

// findSSHBinary finds the ssh executable path on Windows
func findSSHBinary() string {
	// Check SSH_CLIENT_SSH environment variable
	if sshPath := os.Getenv("SSH_CLIENT_SSH"); sshPath != "" {
		return sshPath
	}

	// Try Windows OpenSSH (installed via settings or optional feature)
	paths := []string{
		filepath.Join(os.Getenv("SystemRoot"), "System32", "OpenSSH", "ssh.exe"),
		filepath.Join(os.Getenv("ProgramFiles"), "OpenSSH", "ssh.exe"),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "OpenSSH", "ssh.exe"),
		"C:\\Windows\\System32\\OpenSSH\\ssh.exe",
	}

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	// Try Git for Windows SSH
	gitPaths := []string{
		filepath.Join(os.Getenv("ProgramFiles"), "Git", "usr", "bin", "ssh.exe"),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "Git", "usr", "bin", "ssh.exe"),
	}

	for _, p := range gitPaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	// Fall back to PATH lookup
	path, err := exec.LookPath("ssh.exe")
	if err != nil {
		log.Fatalf("ssh.exe not found in PATH: %v", err)
	}
	return path
}

func NewClient(remoteHost string, remotePort, localPort int, username, password string) (*Client, error) {
	// Create socket directory
	socketDir := filepath.Join(os.Getenv("TEMP"), "ssh-forwarder")
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

	// Find ssh binary
	sshPath := findSSHBinary()
	cmdStr := sshPath + " " + strings.Join(args, " ")
	log.Printf("Executing SSH command: %s", cmdStr)

	cmd := exec.Command(sshPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

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
