package ssh

import (
	"fmt"
	"log"
	"sync"

	"ssh-forwarder/config"

	"golang.org/x/crypto/ssh"
)

type Client struct {
	config   *config.Config
	conn     *ssh.Client
	mu       sync.RWMutex
	channels map[string]*Channel
}

type Channel struct {
	ch         ssh.Channel
	clientConn interface{} // net.Conn or similar
}

func NewClient(cfg *config.Config) (*Client, error) {
	authMethods := BuildAuthMethod(cfg.Username, cfg.Password)

	sshConfig := &ssh.ClientConfig{
		User: cfg.Username,
	}
	if len(authMethods) > 0 {
		sshConfig.Auth = authMethods
	}

	addr := cfg.RemoteHost
	if cfg.RemotePort != 0 {
		addr = fmt.Sprintf("%s:%d", cfg.RemoteHost, cfg.RemotePort)
	}

	log.Printf("Connecting to SSH server: %s", addr)
	conn, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return nil, err
	}

	log.Println("Connected to SSH server")

	return &Client{
		config:   cfg,
		conn:     conn,
		channels: make(map[string]*Channel),
	}, nil
}

func (c *Client) OpenChannel() (ssh.Channel, <-chan *ssh.Request, error) {
	return c.conn.OpenChannel("session", nil)
}

func (c *Client) Close() {
	if c.conn != nil {
		c.conn.Close()
		log.Println("SSH connection closed")
	}
}

func (c *Client) GetConn() *ssh.Client {
	return c.conn
}
