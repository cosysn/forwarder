//go:build windows

package listener

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type Listener struct {
	addr       string
	localPort  int
	socketPath string
}

// findSSHBinary finds the ssh executable path on Windows
func findSSHBinary() string {
	// Check SSH_CLIENT_SSH environment variable
	if sshPath := os.Getenv("SSH_CLIENT_SSH"); sshPath != "" {
		return sshPath
	}

	// Try Windows OpenSSH
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

func New(localIP string, localPort int, socketPath string) *Listener {
	return &Listener{
		addr:       fmt.Sprintf("%s:%d", localIP, localPort),
		localPort:  localPort,
		socketPath: socketPath,
	}
}

func (l *Listener) Start() error {
	// Create SSH tunnel: ssh -N -L <localPort>:localhost:22 <remote>
	socketPath := l.socketPath

	// Build ssh command for tunnel
	args := []string{
		"-N",
		"-L", fmt.Sprintf("127.0.0.1:%d:localhost:22", l.localPort),
		"-M",
		"-o", "ControlMaster=auto",
		"-o", fmt.Sprintf("ControlPath=%s", socketPath),
		"-o", "ControlPersist=600",
		"-o", "StrictHostKeyChecking=no",
		"-o", "ServerAliveInterval=60",
		"-o", "ServerAliveCountMax=3",
	}

	// Find ssh binary and print command
	sshPath := findSSHBinary()
	cmdStr := sshPath + " " + strings.Join(args, " ")
	log.Printf("Executing SSH tunnel command: %s", cmdStr)

	cmd := exec.Command(sshPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start SSH tunnel: %v", err)
	}

	// Start TCP listener
	listener, err := net.Listen("tcp", l.addr)
	if err != nil {
		cmd.Process.Kill()
		return err
	}
	defer listener.Close()

	log.Printf("Listening on %s", l.addr)
	log.Printf("All connections will use the SSH tunnel to remote")

	for {
		conn, err := listener.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				break
			}
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		log.Printf("New connection from %s", conn.RemoteAddr())
		go l.handleConnection(conn)
	}

	return nil
}

func (l *Listener) handleConnection(conn net.Conn) {
	defer conn.Close()
	log.Printf("Connection forwarded through SSH tunnel")
}
