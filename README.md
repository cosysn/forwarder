# SSH Forwarder

A lightweight SSH multiplexing proxy written in Go.

## Features

- **Multiplexing**: Multiple local clients share a single SSH connection
- **Channel isolation**: Each client gets its own SSH channel
- **Flexible auth**: Support for password authentication or no authentication
- **Cross-platform**: Linux, macOS, Windows support

## Usage

### Build

```bash
# Build for current platform
go build -o ssh-forwarder .

# Build for all platforms
./build.sh
```

### Run

```bash
# With authentication
./ssh-forwarder \
    --local-port 2222 \
    --remote-host test.devpod \
    --username root \
    --password yourpassword

# Without authentication
./ssh-forwarder \
    --local-port 2222 \
    --remote-host 192.168.1.100
```

### Parameters

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--local-port` | Yes | - | Local port to listen on |
| `--local-ip` | No | 0.0.0.0 | Local IP to bind |
| `--remote-host` | Yes | - | Remote SSH server address |
| `--remote-port` | No | 22 | Remote SSH port |
| `--username` | No | - | SSH username |
| `--password` | No | - | SSH password |

## How it works

```
┌──────────┐     ┌──────────┐     ┌──────────┐
│ SSH Client│ ──▶ │ Forwarder │ ──▶ │ SSH Server│
│           │ :2222│ (single  │     │           │
└──────────┘     │  SSH conn)│     └──────────┘
                  └──────────┘
                       │
                  Multiple clients share
                  one SSH connection
```

## License

MIT
