# bbot Integration

Portex outputs BBOT-compatible NDJSON events so results flow directly into the phantom-easm pipeline without any transformation.

## Quick Integration

```bash
# Run Portex and pipe into bbot's stdin module
sudo ./bin/portex scan -t 10.0.0.1 -p top1000 --mode syn --output bbot | \
  bbot -m stdin -o json -o neo4j

# Or write to file then load
sudo ./bin/portex scan -t 10.0.0.1 -p top1000 --output bbot \
  --output-file /tmp/portex_scan
bbot -m stdin < /tmp/portex_scan.bbot.ndjson
```

## phantom-easm Pipeline

Portex is designed to run as a bbot module inside the phantom-easm pipeline:

```yaml
# phantom config excerpt
modules:
  portex:
    command: >
      sudo portex scan
        -t {target}
        -p top1000
        --mode stealth
        --rl --mutate --mimic --llm
        --output bbot
        --session-id {session_id}
    output_format: bbot_ndjson
```

### Proxy compatibility

phantom-easm-v3 sets `HTTP_PROXY` and `SOCKS5_PROXY` env vars for all modules. Portex reads these at startup and wires them into all outbound connections (LLM API calls, Ollama calls). Raw packet scans bypass the proxy (they go directly via the network interface).

```bash
# phantom sets these; portex honours them automatically
export HTTP_PROXY=http://10.10.10.1:8080
export SOCKS5_PROXY=socks5://10.10.10.1:1080
sudo -E ./bin/portex scan -t 10.0.0.1 -p top100 --llm
```

### Session ID correlation

Pass `--session-id` to tag all events with the phantom session. The data-router uses this to associate Portex events with the correct scan run.

```bash
sudo ./bin/portex scan -t 10.0.0.1 -p top1000 \
  --output bbot --session-id phantom-abc123
```

## Event Schema Reference

### OPEN_TCP_PORT

Emitted for every port in `open` state.

```json
{
  "type": "OPEN_TCP_PORT",
  "id": "<uuid5(type+host+port)>",
  "data": {
    "host": "10.0.0.1",
    "port": 443,
    "proto": "tcp",
    "status": "open",
    "service": "https",
    "version": "nginx/1.25.0",
    "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.25.0",
    "ttl": 64
  },
  "tags": ["portex", "tcp", "open"],
  "module": "portex",
  "scan_id": "f47ac10b-...",
  "timestamp": "2026-04-13T18:00:41Z"
}
```

### TECHNOLOGY

Emitted when `--service-detect` identifies a technology.

```json
{
  "type": "TECHNOLOGY",
  "id": "<uuid5>",
  "data": {
    "host": "10.0.0.1",
    "port": 443,
    "tech": "nginx",
    "version": "1.25.0",
    "cpe": "cpe:/a:nginx:nginx:1.25.0"
  },
  "tags": ["portex", "service-detection"],
  "module": "portex",
  "scan_id": "f47ac10b-...",
  "timestamp": "2026-04-13T18:00:41Z"
}
```

### VULNERABILITY

Emitted when `--llm` finds CVEs for a port.

```json
{
  "type": "VULNERABILITY",
  "id": "<uuid5>",
  "data": {
    "host": "10.0.0.1",
    "port": 443,
    "severity": "high",
    "cves": ["CVE-2023-44487", "CVE-2021-41773"],
    "summary": "nginx 1.25.0 is affected by HTTP/2 Rapid Reset..."
  },
  "tags": ["portex", "llm-enriched"],
  "module": "portex",
  "scan_id": "f47ac10b-...",
  "timestamp": "2026-04-13T18:00:43Z"
}
```

## Deduplication

Event IDs are UUID v5 (SHA-1 over namespace + `type:host:port`). The phantom data-router detects duplicate IDs and discards them — safe to run multiple Portex instances against overlapping targets.

## Validate NDJSON Output

```bash
sudo ./bin/portex scan -t 127.0.0.1 -p 22 --output bbot | \
  python3 -c "import sys, json; [json.loads(l) for l in sys.stdin]; print('valid')"
```
