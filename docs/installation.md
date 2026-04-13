# Installation

## System Requirements

- Linux (raw sockets require Linux kernel ≥ 4.x)
- Go 1.22 or later
- libpcap-dev (for raw packet capture)
- Root / CAP_NET_RAW for SYN/UDP/ACK/FIN/XMAS/NULL scan modes
- TCP connect mode (`--mode connect`) works without root

## Install libpcap

```bash
# Debian / Ubuntu / Kali
sudo apt-get install -y libpcap-dev

# Arch Linux
sudo pacman -S libpcap

# Fedora / RHEL
sudo dnf install -y libpcap-devel

# Alpine
apk add libpcap-dev
```

## Build from Source

```bash
git clone https://github.com/m4rvxpn/portex
cd portex

# Standard dynamic binary (requires libpcap.so at runtime)
make build
# → bin/portex

# Static binary — no external libs needed, but no raw socket support
make build-static
# → bin/portex-static

# Verify
./bin/portex --version
```

## Grant Capabilities (avoid running as root)

Instead of `sudo`, grant the binary the specific capabilities it needs:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./bin/portex
./bin/portex scan -t 127.0.0.1 -p 22,80 --mode syn
```

## Docker

```bash
# Build image
docker build -t portex:latest .

# Run with required capabilities
docker run --rm \
  --cap-add NET_RAW \
  --cap-add NET_ADMIN \
  --network host \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  portex:latest scan -t 10.0.0.1 -p top1000 --mode syn
```

The Dockerfile is a two-stage build:
- Stage 1: `golang:1.24-alpine` — compiles the binary with CGO + libpcap
- Stage 2: `alpine:3.19` — copies binary + libpcap only, minimal attack surface

## Configuration File

Portex loads configuration from `~/.portex.yaml` or a path set with `--config`:

```yaml
# ~/.portex.yaml
ports: top1000
mode: syn
timing: 3
goroutines: 5000
service_detect: true
os_detect: false
llm_provider: claude
output:
  - json
  - bbot
```

Environment variables override file settings (prefix: `PORTEX_`):

```bash
export PORTEX_GOROUTINES=2000
export PORTEX_TIMING=4
export ANTHROPIC_API_KEY=sk-ant-...
```

## LLM Setup

### Claude (Anthropic)

```bash
export ANTHROPIC_API_KEY=sk-ant-api03-...
sudo -E ./bin/portex scan -t 10.0.0.1 -p top100 --llm --llm-provider claude
```

### Ollama (local)

```bash
# Start Ollama with a supported model
ollama pull llama3
ollama serve

sudo ./bin/portex scan -t 10.0.0.1 -p top100 --llm --llm-provider ollama
```

## Verify Installation

```bash
# Check help
./bin/portex --help
./bin/portex scan --help

# Loopback test (no root needed with --mode connect)
./bin/portex scan -t 127.0.0.1 -p 22,80,443 --mode connect --output json

# Full test with raw sockets
sudo ./bin/portex scan -t 127.0.0.1 -p 22 --mode syn --output json -v
```

## Troubleshooting

**`operation not permitted` on packet send**
Grant `CAP_NET_RAW` or run with `sudo`.

**`no suitable device found` from libpcap**
The interface auto-detection uses a UDP dial to 8.8.8.8. If there is no default route, specify the interface explicitly (config `interface` key).

**`ANTHROPIC_API_KEY not set`**
The `--llm` flag requires the env var. Use `sudo -E` to preserve the environment when running as root.

**Build fails: `cannot find -lpcap`**
Install `libpcap-dev` (Debian) or `libpcap-devel` (RPM). For static builds use `make build-static`.
