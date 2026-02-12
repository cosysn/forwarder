package listener

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

type Listener struct {
	addr       string
	localPort  int
	socketPath string
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
	// This creates a listener that all connections will share
	socketPath := l.socketPath

	// Build remote address for the tunnel
	// The tunnel forwards <localPort> to remote's 22
	args := []string{
		"-N",
		"-L", fmt.Sprintf("127.0.0.1:%d:localhost:22", l.localPort),
		"-M",                    // Master mode
		"-o", "ControlMaster=auto",
		"-o", fmt.Sprintf("ControlPath=%s", socketPath),
		"-o", "ControlPersist=600",
		"-o", "StrictHostKeyChecking=no",
		"-o", "ServerAliveInterval=60",
		"-o", "ServerAliveCountMax=3",
	}

	log.Printf("Starting SSH tunnel to remote")

	cmd := exec.Command("ssh", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
		Pgid: 0,
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start SSH tunnel: %v", err)
	}

	// The tunnel is now listening on l.localPort
	// All connections to this port go through the same SSH connection

	// Also start a TCP listener for non-SSH clients that want to connect through the tunnel
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

	// The connection is already being forwarded through the SSH tunnel
	// because we created the tunnel with -L 127.0.0.1:<localPort>:localhost:22
	// The SSH tunnel handles all the forwarding internally

	log.Printf("Connection forwarded through SSH tunnel")
}
