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
	proxyConn *proxyConn
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
		config:    clientConfig,
		host:      hostname,
		port:      port,
		user:      user,
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

// proxyConn implements net.Conn for ProxyCommand
type proxyConn struct {
	stdin  io.WriteCloser
	stdout io.Reader
	cmd    *exec.Cmd
	local  net.Addr
	remote  net.Addr
}

func newProxyConn(stdin io.WriteCloser, stdout io.Reader, cmd *exec.Cmd) *proxyConn {
	return &proxyConn{
		stdin:  stdin,
		stdout: stdout,
		cmd:    cmd,
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
	p.stdin.Close()
	p.cmd.Wait()
	return nil
}

func (p *proxyConn) LocalAddr() net.Addr  { return p.local }
func (p *proxyConn) RemoteAddr() net.Addr { return p.remote }
func (p *proxyConn) SetDeadline(t time.Time) error   { return nil }
func (p *proxyConn) SetReadDeadline(t time.Time) error  { return nil }
func (p *proxyConn) SetWriteDeadline(t time.Time) error { return nil }

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

		// Use sh on Unix, cmd on Windows
		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.Command("cmd", "/c", proxyCmdStr)
		} else {
			cmd = exec.Command("sh", "-c", proxyCmdStr)
		}
		stdinPipe, err := cmd.StdinPipe()
		if err != nil {
			return fmt.Errorf("failed to get stdin pipe: %v", err)
		}
		stdoutPipe, err := cmd.StdoutPipe()
		if err != nil {
			return fmt.Errorf("failed to get stdout pipe: %v", err)
		}

		c.proxyConn = newProxyConn(stdinPipe, stdoutPipe, cmd)
		conn = c.proxyConn

		if err := cmd.Start(); err != nil {
			return fmt.Errorf("failed to start ProxyCommand: %v", err)
		}
		log.Printf("ProxyCommand started")
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
	addr := fmt.Sprintf("%s:%s", c.host, c.port)
	sshClient, chans, reqs, err := ssh.NewClientConn(conn, addr, c.config)
	if err != nil {
		return fmt.Errorf("failed to establish SSH connection: %v", err)
	}

	c.client = ssh.NewClient(sshClient, chans, reqs)
	log.Printf("SSH connection established")

	return nil
}

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
