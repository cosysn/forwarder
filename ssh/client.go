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

	"github.com/creack/pty"
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
	var proxyCmd *exec.Cmd

	if proxyCommand != "" {
		// Use ProxyCommand with PTY to make it interactive
		proxyCmdStr := parseProxyCommand(proxyCommand, c.host, c.port, c.user)
		log.Printf("Executing ProxyCommand with PTY: %s", proxyCmdStr)

		if runtime.GOOS == "windows" {
			proxyCmd = exec.Command("cmd", "/c", proxyCmdStr)
		} else {
			proxyCmd = exec.Command("sh", "-c", proxyCmdStr)
		}

		// Create PTY for interactive terminal
		ptyFile, ttyFile, err := pty.Open()
		if err != nil {
			return fmt.Errorf("failed to open PTY: %v", err)
		}

		proxyCmd.Stdin = ttyFile
		proxyCmd.Stdout = ttyFile
		proxyCmd.Stderr = ttyFile

		if err := proxyCmd.Start(); err != nil {
			return fmt.Errorf("failed to start ProxyCommand: %v", err)
		}

		log.Printf("ProxyCommand started with PTY (PID: %d)", proxyCmd.Process.Pid)

		// Close TTY in parent - child has its own copy
		ttyFile.Close()

		// Give proxy time to establish connection
		time.Sleep(2 * time.Second)

		// Check if process is still running
		if proxyCmd.ProcessState != nil && proxyCmd.ProcessState.Exited() {
			exitCode := proxyCmd.ProcessState.ExitCode()
			log.Printf("ProxyCommand exited with code: %d", exitCode)
			return fmt.Errorf("ProxyCommand exited immediately with code: %d", exitCode)
		}

		proxyConn := newPtyConn(proxyCmd, ptyFile)
		c.proxyConn = proxyConn
		conn = proxyConn

		log.Printf("ProxyCommand ready with PTY")

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
	log.Printf("Starting SSH handshake to %s:%s...", c.host, c.port)

	type connResult struct {
		client *ssh.Client
		err    error
	}
	resultChan := make(chan connResult, 1)

	go func() {
		log.Printf("goroutine: starting NewClientConn...")
		addr := fmt.Sprintf("%s:%s", c.host, c.port)
		log.Printf("goroutine: dialing %s...", addr)
		sshClient, chans, reqs, err := ssh.NewClientConn(conn, addr, c.config)
		if err != nil {
			log.Printf("goroutine: NewClientConn error: %v", err)
			resultChan <- connResult{err: err}
			return
		}
		log.Printf("goroutine: NewClientConn success, creating client...")
		resultChan <- connResult{client: ssh.NewClient(sshClient, chans, reqs)}
	}()

	select {
	case r := <-resultChan:
		if r.err != nil {
			return fmt.Errorf("failed to establish SSH connection: %v", r.err)
		}
		c.client = r.client
		log.Printf("SSH connection established!")
	case <-time.After(30 * time.Second):
		log.Printf("TIMEOUT: handshake hung for 30s, checking process state...")
		if proxyCmd != nil && proxyCmd.ProcessState != nil {
			log.Printf("Process exited with code: %d", proxyCmd.ProcessState.ExitCode())
		} else {
			log.Printf("Process still running or no ProxyCommand")
		}
		return fmt.Errorf("SSH handshake timed out after 30s")
	}

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

// ptyConn implements net.Conn using PTY for ProxyCommand
type ptyConn struct {
	cmd    *exec.Cmd
	pty    *os.File
	done   chan struct{}
	local  net.Addr
	remote net.Addr
}

func newPtyConn(cmd *exec.Cmd, ptyFile *os.File) *ptyConn {
	return &ptyConn{
		cmd:   cmd,
		pty:   ptyFile,
		done:  make(chan struct{}),
		local:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0},
		remote: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0},
	}
}

func (p *ptyConn) Read(b []byte) (n int, err error) {
	return p.pty.Read(b)
}

func (p *ptyConn) Write(b []byte) (n int, err error) {
	return p.pty.Write(b)
}

func (p *ptyConn) Close() error {
	if p.pty != nil {
		p.pty.Close()
	}
	if p.cmd.Process != nil {
		p.cmd.Process.Kill()
	}
	p.cmd.Wait()
	return nil
}

func (p *ptyConn) LocalAddr() net.Addr  { return p.local }
func (p *ptyConn) RemoteAddr() net.Addr { return p.remote }
func (p *ptyConn) SetDeadline(t time.Time) error   { return nil }
func (p *ptyConn) SetReadDeadline(t time.Time) error  { return nil }
func (p *ptyConn) SetWriteDeadline(t time.Time) error { return nil }

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
