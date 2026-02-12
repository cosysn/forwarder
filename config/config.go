package config

import (
	"flag"
	"fmt"
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
