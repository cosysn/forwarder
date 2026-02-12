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
