package ssh

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// SSHConfig represents a parsed SSH config file
type SSHConfig struct {
	Hosts map[string]*HostConfig
}

// HostConfig represents configuration for a specific host
type HostConfig struct {
	HostName      string
	User          string
	Port          string
	ProxyCommand  string
	IdentityFile  string
	ForwardAgent  string
	OtherOptions  map[string]string
}

// ParseSSHConfig parses ~/.ssh/config file
func ParseSSHConfig() (*SSHConfig, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %v", err)
	}

	configPath := filepath.Join(home, ".ssh", "config")
	return ParseSSHConfigFile(configPath)
}

// ParseSSHConfigFile parses a specific SSH config file
func ParseSSHConfigFile(configPath string) (*SSHConfig, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	config := &SSHConfig{
		Hosts: make(map[string]*HostConfig),
	}

	lines := strings.Split(string(data), "\n")
	var currentHost *HostConfig
	var currentPatterns []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		key := strings.ToLower(parts[0])
		value := strings.Join(parts[1:], " ")

		switch key {
		case "host":
			// Save previous host config
			for _, pattern := range currentPatterns {
				config.Hosts[pattern] = currentHost
			}

			// Start new host
			currentPatterns = strings.Fields(value)
			currentHost = &HostConfig{
				OtherOptions: make(map[string]string),
			}

		case "hostname":
			if currentHost != nil {
				currentHost.HostName = value
			}

		case "user":
			if currentHost != nil {
				currentHost.User = value
			}

		case "port":
			if currentHost != nil {
				currentHost.Port = value
			}

		case "proxycommand":
			if currentHost != nil {
				currentHost.ProxyCommand = value
			}

		case "identityfile":
			if currentHost != nil {
				currentHost.IdentityFile = value
			}

		case "forwardagent":
			if currentHost != nil {
				currentHost.ForwardAgent = value
			}

		default:
			if currentHost != nil {
				currentHost.OtherOptions[key] = value
			}
		}
	}

	// Save last host config
	for _, pattern := range currentPatterns {
		config.Hosts[pattern] = currentHost
	}

	return config, nil
}

// FindHostConfig finds the matching host configuration for a given hostname
func (c *SSHConfig) FindHostConfig(hostname string) *HostConfig {
	// First try exact match
	if host, ok := c.Hosts[hostname]; ok {
		return host
	}

	// Try pattern matching
	for pattern, host := range c.Hosts {
		if matched, _ := matchHost(pattern, hostname); matched {
			return host
		}
	}

	return nil
}

// matchHost checks if a hostname matches a host pattern
func matchHost(pattern, hostname string) (bool, error) {
	// Handle wildcards
	pattern = strings.ReplaceAll(pattern, "*", ".*")
	pattern = "^" + pattern + "$"

	// Simple regex match
	return strings.HasPrefix(hostname, pattern[:len(pattern)-2]) &&
		   hostname == pattern[1:len(pattern)-1] ||
		   (len(hostname) >= 2 && strings.HasSuffix(hostname, pattern[1:len(pattern)-1])), nil
}

// GetProxyCommand returns the ProxyCommand for a hostname, if any
func (c *SSHConfig) GetProxyCommand(hostname string) string {
	hostConfig := c.FindHostConfig(hostname)
	if hostConfig != nil && hostConfig.ProxyCommand != "" {
		return hostConfig.ProxyCommand
	}
	return ""
}

// ResolveHostname returns the actual hostname from config
func (c *SSHConfig) ResolveHostname(hostname string) string {
	hostConfig := c.FindHostConfig(hostname)
	if hostConfig != nil && hostConfig.HostName != "" {
		return hostConfig.HostName
	}
	return hostname
}

// ResolveUser returns the user from config
func (c *SSHConfig) ResolveUser(hostname string) string {
	hostConfig := c.FindHostConfig(hostname)
	if hostConfig != nil && hostConfig.User != "" {
		return hostConfig.User
	}
	return ""
}

// ResolvePort returns the port from config
func (c *SSHConfig) ResolvePort(hostname string) string {
	hostConfig := c.FindHostConfig(hostname)
	if hostConfig != nil && hostConfig.Port != "" {
		return hostConfig.Port
	}
	return ""
}

// ExecuteProxyCommand executes a ProxyCommand and returns the connection
func ExecuteProxyCommand(proxyCommand string) (*exec.Cmd, error) {
	// Replace %h with target host, %p with port
	// For simplicity, just execute as-is with shell
	cmd := exec.Command("sh", "-c", proxyCommand)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start ProxyCommand: %v", err)
	}

	return cmd, nil
}

// TestProxyCommand tests if a ProxyCommand would work
func TestProxyCommand(proxyCommand string) bool {
	cmd := exec.Command("sh", "-c", proxyCommand+" echo test")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return err == nil && strings.Contains(stdout.String(), "test")
}
