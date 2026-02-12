package main

import (
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
