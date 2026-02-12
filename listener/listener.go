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
