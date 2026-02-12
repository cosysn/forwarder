package ssh

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type Client struct {
	config    *ssh.ClientConfig
	host      string
	port      string
	user      string
	client    *ssh.Client
	proxyCmd  *exec.Cmd
	proxyConn net.Conn
}

type Channel struct {
	ch ssh.Channel
}

// NewClient creates a new SSH client with config and ProxyCommand support
func NewClient(remoteHost string, remotePort, localPort int, username, password string) (*Client, error) {
	// Parse SSH config
	sshConfig, err := ParseSSHConfig()
	if err != nil && !os.IsNotExist(err) {
		log.Printf("Warning: Failed to parse SSH config: %v", err)
	}

	// Resolve hostname from config
	hostname := remoteHost
	if sshConfig != nil {
		hostname = sshConfig.ResolveHostname(remoteHost)
	}

	// Resolve user from config or use provided
	user := username
	if user == "" && sshConfig != nil {
		user = sshConfig.ResolveUser(remoteHost)
	}
	if user == "" {
		user = os.Getenv("USER")
		if user == "" {
			user = "root"
		}
	}

	// Resolve port from config or use provided
	port := "22"
	if remotePort != 0 {
		port = strconv.Itoa(remotePort)
	}
	if sshConfig != nil {
		configPort := sshConfig.ResolvePort(remoteHost)
		if configPort != "" {
			port = configPort
		}
	}

	// Get ProxyCommand if configured
	proxyCommand := ""
	if sshConfig != nil {
		proxyCommand = sshConfig.GetProxyCommand(remoteHost)
	}

	log.Printf("Target: %s@%s:%s (ProxyCommand: %v)", user, hostname, port, proxyCommand != "")

	// Build SSH client config
	clientConfig := &ssh.ClientConfig{
		User: user,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// Handle password auth
	if password != "" {
		clientConfig.Auth = []ssh.AuthMethod{
			ssh.Password(password),
		}
	}

	// Try to load key from agent or file
	if keyAuth := getKeyAuth(); keyAuth != nil {
		clientConfig.Auth = append(clientConfig.Auth, keyAuth)
	}

	return &Client{
		config: clientConfig,
		host:   hostname,
		port:   port,
		user:   user,
	}, nil
}

func getKeyAuth() ssh.AuthMethod {
	// Try SSH agent
	if agentAuth := getSSHAgentAuth(); agentAuth != nil {
		return agentAuth
	}

	// Try default key files
	home, _ := os.UserHomeDir()
	keyFiles := []string{
		filepath.Join(home, ".ssh", "id_rsa"),
		filepath.Join(home, ".ssh", "id_ed25519"),
		filepath.Join(home, ".ssh", "id_ecdsa"),
	}

	for _, keyFile := range keyFiles {
		if auth := loadKeyFile(keyFile); auth != nil {
			return auth
		}
	}

	return nil
}

func getSSHAgentAuth() ssh.AuthMethod {
	agentSocket := os.Getenv("SSH_AUTH_SOCK")
	if agentSocket == "" {
		return nil
	}

	cmd := exec.Command("ssh-add", "-L")
	cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+agentSocket)
	var keys bytes.Buffer
	cmd.Stdout = &keys
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return nil
	}

	keysStr := keys.String()
	if keysStr == "" {
		return nil
	}

	var certs []ssh.Signer
	for _, line := range strings.Split(keysStr, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		signer, err := ssh.ParsePrivateKey([]byte(line))
		if err != nil {
			continue
		}
		certs = append(certs, signer)
	}

	if len(certs) == 0 {
		return nil
	}

	return ssh.PublicKeys(certs...)
}

func loadKeyFile(path string) ssh.AuthMethod {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil
	}

	return ssh.PublicKeys(signer)
}

// parseProxyCommand parses %h, %p, %r placeholders in ProxyCommand
func parseProxyCommand(cmd, host, port, user string) string {
	cmd = strings.ReplaceAll(cmd, "%h", host)
	cmd = strings.ReplaceAll(cmd, "%p", port)
	cmd = strings.ReplaceAll(cmd, "%r", user)
	return cmd
}

// Connect establishes the SSH connection, using ProxyCommand if configured
func (c *Client) Connect() error {
	if c.client != nil {
		return nil
	}

	// First, get ProxyCommand from config
	var proxyCommand string
	sshConfig, _ := ParseSSHConfig()
	if sshConfig != nil {
		proxyCommand = sshConfig.GetProxyCommand(c.host)
	}

	var conn net.Conn
	var err error

	if proxyCommand != "" {
		// Use ProxyCommand
		proxyCmdStr := parseProxyCommand(proxyCommand, c.host, c.port, c.user)
		log.Printf("Executing ProxyCommand: %s", proxyCmdStr)

		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.Command("cmd", "/c", proxyCmdStr)
		} else {
			cmd = exec.Command("sh", "-c", proxyCmdStr)
		}

		// Use StdinPipe/StdoutPipe for proper subprocess communication
		stdinPipe, err := cmd.StdinPipe()
		if err != nil {
			return fmt.Errorf("failed to get stdin pipe: %v", err)
		}
		stdoutPipe, err := cmd.StdoutPipe()
		if err != nil {
			return fmt.Errorf("failed to get stdout pipe: %v", err)
		}
		stderrPipe, err := cmd.StderrPipe()
		if err != nil {
			return fmt.Errorf("failed to get stderr pipe: %v", err)
		}

		// Start command
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("failed to start ProxyCommand: %v", err)
		}

		log.Printf("ProxyCommand started (PID: %d)", cmd.Process.Pid)

		// Read stderr asynchronously to capture any errors
		stderrDone := make(chan bool, 1)
		go func() {
			buf := make([]byte, 4096)
			for {
				n, err := stderrPipe.Read(buf)
				if n > 0 {
					log.Printf("ProxyCommand stderr: %s", string(buf[:n]))
				}
				if err != nil {
					break
				}
			}
			stderrDone <- true
		}()

		// Give proxy time to establish connection
		time.Sleep(2 * time.Second)

		// Check if process is still running
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			// Wait for stderr to be read
			select {
			case <-stderrDone:
			case <-time.After(1 * time.Second):
			}
			exitCode := cmd.ProcessState.ExitCode()
			log.Printf("ProxyCommand exited with code: %d", exitCode)
			return fmt.Errorf("ProxyCommand exited immediately with code: %d", exitCode)
		}

		proxyConn := newProxyConn(cmd, stdinPipe, stdoutPipe)
		c.proxyConn = proxyConn
		conn = proxyConn

		// Start a goroutine to keep reading from stdout to prevent EOF
		go func() {
			buf := make([]byte, 4096)
			for {
				n, err := stdoutPipe.Read(buf)
				if n > 0 {
					log.Printf("ProxyCommand stdout: %s", string(buf[:n]))
				}
				if err != nil {
					exited := cmd.ProcessState != nil && cmd.ProcessState.Exited()
					log.Printf("ProxyCommand stdout closed: %v (exited=%v)", err, exited)
					close(proxyConn.done)
					break
				}
			}
		}()

		log.Printf("ProxyCommand ready")

	} else {
		// Direct TCP connection
		addr := fmt.Sprintf("%s:%s", c.host, c.port)
		log.Printf("Connecting directly to %s", addr)
		conn, err = net.DialTimeout("tcp", addr, 10*time.Second)
		if err != nil {
			return fmt.Errorf("failed to dial SSH: %v", err)
		}
	}

	// Establish SSH connection over the connection
	log.Printf("Starting SSH handshake...")
	addr := fmt.Sprintf("%s:%s", c.host, c.port)
	sshClient, chans, reqs, err := ssh.NewClientConn(conn, addr, c.config)
	if err != nil {
		return fmt.Errorf("failed to establish SSH connection: %v", err)
	}

	c.client = ssh.NewClient(sshClient, chans, reqs)
	log.Printf("SSH connection established")

	return nil
}

// proxyConn implements net.Conn for ProxyCommand
type proxyConn struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.Reader
	done   chan struct{}
	local  net.Addr
	remote net.Addr
}

func newProxyConn(cmd *exec.Cmd, stdin io.WriteCloser, stdout io.Reader) *proxyConn {
	return &proxyConn{
		cmd:    cmd,
		stdin:  stdin,
		stdout: stdout,
		done:   make(chan struct{}),
		local:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0},
		remote: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0},
	}
}

func (p *proxyConn) Read(b []byte) (n int, err error) {
	return p.stdout.Read(b)
}

func (p *proxyConn) Write(b []byte) (n int, err error) {
	return p.stdin.Write(b)
}

func (p *proxyConn) Close() error {
	// Close stdin first
	if p.stdin != nil {
		p.stdin.Close()
	}

	// Wait for the command to exit or timeout
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		// Force kill if still running
		if p.cmd.Process != nil {
			p.cmd.Process.Kill()
		}
	}

	// Wait for the process
	if p.cmd.Process != nil {
		p.cmd.Wait()
	}

	return nil
}

func (p *proxyConn) LocalAddr() net.Addr  { return p.local }
func (p *proxyConn) RemoteAddr() net.Addr { return p.remote }
func (p *proxyConn) SetDeadline(t time.Time) error   { return nil }
func (p *proxyConn) SetReadDeadline(t time.Time) error  { return nil }
func (p *proxyConn) SetWriteDeadline(t time.Time) error { return nil }

// OpenChannel opens a new SSH channel
func (c *Client) OpenChannel() (ssh.Channel, <-chan *ssh.Request, error) {
	if c.client == nil {
		if err := c.Connect(); err != nil {
			return nil, nil, err
		}
	}

	return c.client.OpenChannel("session", nil)
}

// GetClient returns the underlying SSH client
func (c *Client) GetClient() *ssh.Client {
	return c.client
}

// Close closes the SSH connection
func (c *Client) Close() {
	if c.client != nil {
		c.client.Close()
		log.Println("SSH connection closed")
	}
	if c.proxyConn != nil {
		c.proxyConn.Close()
	}
}
