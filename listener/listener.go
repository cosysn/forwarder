package listener

import (
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

type Listener struct {
	addr      string
	localPort int
	client    *ssh.Client
}

func New(localIP string, localPort int, client *ssh.Client) *Listener {
	return &Listener{
		addr:      fmt.Sprintf("%s:%d", localIP, localPort),
		localPort: localPort,
		client:    client,
	}
}

func (l *Listener) Start() error {
	// Listen on local port
	listener, err := net.Listen("tcp", l.addr)
	if err != nil {
		return err
	}
	defer listener.Close()

	log.Printf("Listening on %s", l.addr)
	log.Printf("All connections will use the SSH connection to %s", l.client.RemoteAddr())

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

	// Open a new channel on the existing SSH connection
	ch, requests, err := l.client.OpenChannel("session", nil)
	if err != nil {
		log.Printf("Failed to open SSH channel: %v", err)
		return
	}
	defer ch.Close()

	// Handle SSH requests
	go func() {
		for req := range requests {
			log.Printf("Received SSH request: %s", req.Type)
			req.Reply(true, nil)
		}
	}()

	log.Printf("SSH channel opened, starting forward")

	// Bidirectional copy
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, err := io.Copy(ch, conn)
		if err != nil {
			log.Printf("Forward error (client -> SSH): %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		_, err := io.Copy(conn, ch)
		if err != nil {
			log.Printf("Forward error (SSH -> client): %v", err)
		}
	}()

	wg.Wait()

	log.Printf("Connection closed")
}
