package main

import (
	"log"
	"os"
	"os/signal"
	"runtime"
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

	client, err := ssh.NewClient(
		cfg.RemoteHost,
		cfg.RemotePort,
		cfg.LocalPort,
		cfg.Username,
		cfg.Password,
	)
	if err != nil {
		log.Fatalf("Failed to create SSH client: %v", err)
	}
	defer client.Close()

	// Connect to SSH server
	if err := client.Connect(); err != nil {
		log.Fatalf("Failed to connect to SSH server: %v", err)
	}

	l := listener.New(cfg.LocalIP, cfg.LocalPort, client.GetClient())

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)

	// Different signals for Unix and Windows
	if runtime.GOOS == "windows" {
		signal.Notify(sigChan, os.Interrupt)
	} else {
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	}

	go func() {
		<-sigChan
		log.Println("Received shutdown signal, closing...")
		client.Close()
		os.Exit(0)
	}()

	if err := l.Start(); err != nil {
		log.Fatalf("Failed to start listener: %v", err)
	}
}
