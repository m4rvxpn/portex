# Configuration

Portex reads configuration from (in priority order, highest to lowest):

1. CLI flags
2. Environment variables (`PORTEX_*`)
3. Config file (`~/.portex.yaml` or `--config <path>`)
4. Built-in defaults

## Default Values

| Option | Default | Description |
|---|---|---|
| `ports` | `top1000` | Port specification |
| `mode` | `syn` | Scan mode |
| `timing` | `3` | T0-T5 timing profile |
| `goroutines` | `5000` | Concurrent probe workers |
| `max-retries` | `6` | Per-port retry limit |
| `max-rtt` | `10s` | Per-probe timeout |
| `batch-size` | `256` | Probe batch size |
| `llm-provider` | `claude` | LLM backend |
| `output` | `json` | Output format(s) |

## Config File

```yaml
# ~/.portex.yaml

# Targeting defaults
ports: top1000
mode: syn
timing: 3
goroutines: 5000
max_retries: 6

# Detection
service_detect: false
os_detect: false
script_scan: false
scripts: []

# AI layers
enable_rl: false
enable_mutator: false
enable_mimicry: false
enable_llm: false
llm_provider: claude   # claude | ollama
ollama_host: http://localhost:11434

# Output
output:
  - json
output_file: ""

# Network
proxy: ""              # socks5://host:port or http://host:port

# Logging
verbose: false
```

## Environment Variables

All config keys are available as `PORTEX_<KEY>` (uppercase, underscores).

| Variable | Example |
|---|---|
| `PORTEX_GOROUTINES` | `5000` |
| `PORTEX_TIMING` | `4` |
| `PORTEX_MODE` | `syn` |
| `PORTEX_PORTS` | `top1000` |
| `PORTEX_ENABLE_LLM` | `true` |
| `PORTEX_LLM_PROVIDER` | `claude` |
| `PORTEX_OLLAMA_HOST` | `http://localhost:11434` |
| `ANTHROPIC_API_KEY` | `sk-ant-...` |
| `HTTP_PROXY` | `http://proxy:8080` |
| `SOCKS5_PROXY` | `socks5://proxy:1080` |

## Port Specifications

| Spec | Ports |
|---|---|
| `80` | single port |
| `80,443,8080` | comma list |
| `1-1024` | range |
| `top100` | nmap's top 100 TCP ports |
| `top1000` | nmap's top 1000 TCP ports |
| `all` | 1-65535 |
| `@/path/to/file` | newline-separated port list |

Combinations: `80,443,8000-8100,top100`

## Timing Profiles

| Level | Name | Max RTT | Min RTT | Probe rate | Notes |
|---|---|---|---|---|---|
| 0 | Paranoid | 5 min | 5 min | 1 PPS | IDS evasion, one port at a time |
| 1 | Sneaky | 30 s | 15 s | 2 PPS | Stealth recon |
| 2 | Polite | 1 s | 400 ms | 10 PPS | Low bandwidth targets |
| 3 | Normal | 200 ms | 100 ms | 100 PPS | Default |
| 4 | Aggressive | 50 ms | 10 ms | 1000 PPS | Fast LAN |
| 5 | Insane | 10 ms | 5 ms | 5000 PPS | Saturate the link |

## Proxy Configuration

```bash
# SOCKS5
SOCKS5_PROXY=socks5://127.0.0.1:1080 sudo -E ./bin/portex scan ...

# HTTP proxy
HTTP_PROXY=http://127.0.0.1:8080 sudo -E ./bin/portex scan ...

# Per-invocation flag
sudo ./bin/portex scan --proxy socks5://127.0.0.1:1080 ...
```

Raw packet scans bypass the proxy (sent directly via the network interface). Only LLM API calls and other outbound HTTP connections use the proxy.

## Multiple Config Files

```bash
# Development config
./bin/portex scan --config ./configs/dev.yaml -t 10.0.0.1 -p 80

# CI config
./bin/portex scan --config ./configs/ci.yaml -t 10.0.0.1 -p 22
```
