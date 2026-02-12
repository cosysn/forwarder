# SSH Forwarder Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a Go-based SSH multiplexing proxy that listens on a local port and forwards connections through a single SSH connection to a remote server, supporting multiple concurrent client connections.

**Architecture:**
- Single process manages one SSH client connection to remote server
- Local TCP listener accepts client connections
- Each client connection gets its own SSH Channel (multiplexed over the single SSH connection)
- Bidirectional data转发 using io.Copy
- Immediate shutdown on SIGINT/SIGTERM

**Tech Stack:**
- Go 1.21+
- golang.org/x/crypto v0.31.0 (SSH protocol implementation)
- Standard library: net, flag, sync, context, os/signal

---

## Implementation Steps

### Task 1: Initialize Go Module

**Files:**
- Create: `go.mod`

**Step 1: Create go.mod**

```bash
cd /home/ubuntu/forwarder
go mod init ssh-forwarder
```

**Step 2: Add dependency**

```bash
go get golang.org/x/crypto@v0.31.0
```

**Step 3: Commit**

```bash
git init
git add go.mod
git commit -m "chore: initialize go module with crypto dependency"
```

---

### Task 2: Create Main Entry Point

**Files:**
- Create: `main.go`

**Step 1: Write main.go**

```go
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"ssh-forwarder/config"
	"ssh-forwarder/listener"
	"ssh-forwarder/ssh"
)

func main() {
	cfg := config.Parse()

	log.Printf("Starting SSH forwarder")
	log.Printf("Local: %s:%d -> Remote: %s:%d",
		cfg.LocalIP, cfg.LocalPort, cfg.RemoteHost, cfg.RemotePort)

	client, err := ssh.NewClient(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to SSH server: %v", err)
	}
	defer client.Close()

	l := listener.New(cfg.LocalIP, cfg.LocalPort, client)

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Received shutdown signal, closing...")
		os.Exit(0)
	}()

	if err := l.Start(); err != nil {
		log.Fatalf("Failed to start listener: %v", err)
	}
}
```

**Step 2: Commit**

```bash
git add main.go
git commit -m "feat: add main entry point with signal handling"
```

---

### Task 3: Create Config Package

**Files:**
- Create: `config/config.go`

**Step 1: Write config.go**

```go
package config

import (
	"flag"
	"fmt"
	"log"
	"os"
)

type Config struct {
	LocalIP      string
	LocalPort    int
	RemoteHost   string
	RemotePort   int
	Username     string
	Password     string
}

func Parse() *Config {
	localIP := flag.String("local-ip", "0.0.0.0", "Local IP to bind")
	localPort := flag.Int("local-port", 0, "Local port to listen (required)")
	remoteHost := flag.String("remote-host", "", "Remote SSH host (required)")
	remotePort := flag.Int("remote-port", 22, "Remote SSH port")
	username := flag.String("username", "", "SSH username (optional)")
	password := flag.String("password", "", "SSH password (optional)")

	flag.Parse()

	if *localPort == 0 {
		fmt.Fprintln(os.Stderr, "--local-port is required")
		os.Exit(1)
	}
	if *remoteHost == "" {
		fmt.Fprintln(os.Stderr, "--remote-host is required")
		os.Exit(1)
	}

	return &Config{
		LocalIP:      *localIP,
		LocalPort:    *localPort,
		RemoteHost:   *remoteHost,
		RemotePort:   *remotePort,
		Username:     *username,
		Password:     *password,
	}
}
```

**Step 2: Commit**

```bash
git add config/config.go
git commit -m "feat: add config package with flag parsing"
```

---

### Task 4: Create SSH Client Package

**Files:**
- Create: `ssh/client.go`
- Create: `ssh/auth.go`

**Step 1: Write ssh/auth.go**

```go
package ssh

import (
	"golang.org/x/crypto/ssh"
)

func BuildAuthMethod(username, password string) []ssh.AuthMethod {
	var authMethods []ssh.AuthMethod

	if username != "" && password != "" {
		authMethods = append(authMethods, ssh.Password(password))
	}

	return authMethods
}
```

**Step 2: Write ssh/client.go**

```go
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

func (c *Client) OpenChannel() (ssh.Channel, error) {
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
```

**Step 3: Commit**

```bash
git add ssh/auth.go ssh/client.go
git commit -m "feat: add ssh client with authentication support"
```

---

### Task 5: Create Listener Package

**Files:**
- Create: `listener/listener.go`

**Step 1: Write listener.go**

```go
package listener

import (
	"fmt"
	"io"
	"log"
	"net"
	"strings"

	"golang.org/x/crypto/ssh"
)

type Listener struct {
	addr   string
	client *ssh.Client
}

func New(localIP string, localPort int, client *ssh.Client) *Listener {
	return &Listener{
		addr:   fmt.Sprintf("%s:%d", localIP, localPort),
		client: client,
	}
}

func (l *Listener) Start() error {
	listener, err := net.Listen("tcp", l.addr)
	if err != nil {
		return err
	}
	defer listener.Close()

	log.Printf("Listening on %s", l.addr)

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

	ch, err := l.client.OpenChannel()
	if err != nil {
		log.Printf("Failed to open SSH channel: %v", err)
		return
	}
	defer ch.Close()

	log.Printf("SSH channel opened, starting forward")

	// Bidirectional copy
	if err := l.forward(ch, conn); err != nil {
		log.Printf("Forward error: %v", err)
	}

	log.Printf("Connection closed")
}

func (l *Listener) forward(ch ssh.Channel, conn net.Conn) error {
	errCh := make(chan error, 2)

	go func() {
		_, err := io.Copy(ch, conn)
		errCh <- err
	}()

	go func() {
		_, err := io.Copy(conn, ch)
		errCh <- err
	}()

	<-errCh
	return nil
}
```

**Step 2: Fix main.go to use correct listener import**

```go
import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"ssh-forwarder/config"
	"ssh-forwarder/listener"
	"ssh-forwarder/ssh"
)
```

**Step 3: Commit**

```bash
git add listener/listener.go
git commit -m "feat: add TCP listener with SSH channel forwarding"
```

---

### Task 6: Test and Fix Compilation Issues

**Step 1: Try to build**

```bash
go build -o ssh-forwarder .
```

**Step 2: Fix any compilation errors**

**Step 3: Commit fixes**

```bash
git add -A
git commit -m "fix: resolve compilation issues"
```

---

### Task 7: Create Build Scripts

**Files:**
- Create: `build.sh` (Linux/macOS)
- Create: `build.bat` (Windows)

**Step 1: Write build.sh**

```bash
#!/bin/bash
set -e

echo "Building ssh-forwarder for multiple platforms..."

# Linux
GOOS=linux GOARCH=amd64 go build -o ssh-forwarder-linux-amd64 .
GOOS=linux GOARCH=arm64 go build -o ssh-forwarder-linux-arm64 .

# macOS
GOOS=darwin GOARCH=amd64 go build -o ssh-forwarder-darwin-amd64 .
GOOS=darwin GOARCH=arm64 go build -o ssh-forwarder-darwin-arm64 .

# Windows
GOOS=windows GOARCH=amd64 go build -o ssh-forwarder-windows-amd64.exe .

echo "Build complete!"
ls -la ssh-forwarder-*
```

**Step 2: Make executable**

```bash
chmod +x build.sh
```

**Step 3: Write build.bat**

```bat
@echo off
echo Building ssh-forwarder for Windows...

go build -o ssh-forwarder-windows-amd64.exe .

echo Build complete!
dir *.exe
```

**Step 4: Commit**

```bash
git add build.sh build.bat
git commit -m "chore: add cross-platform build scripts"
```

---

### Task 8: Verify with Integration Test

**Step 1: Start the forwarder**

```bash
./ssh-forwarder --local-port 2222 --remote-host localhost --remote-port 22 --username test --password test123 2>&1 | head -20
```

**Step 2: Test with SSH client**

```bash
ssh -p 2222 user@127.0.0.1 echo "test"
```

**Step 3: Verify output**

Expected: Connection logs showing listener start, connection accepted, channel opened, forward started, connection closed.

**Step 4: Commit test results**

```bash
git log --oneline -3
```

---

## Summary

**Estimated files to create/modify:**
- `go.mod` - dependency
- `main.go` - entry point
- `config/config.go` - flag parsing
- `ssh/auth.go` - SSH authentication
- `ssh/client.go` - SSH client management
- `listener/listener.go` - TCP listener + forwarding
- `build.sh` / `build.bat` - build scripts

**Estimated commits:** 7-8
