# Output Formats

Use `--output` with a comma-separated list of formats. Use `--output-file` to set a base path; each format appends its own extension.

```bash
sudo ./bin/portex scan -t 10.0.0.1 -p top1000 \
  --output json,bbot,xml,csv,nuclei-yaml \
  --output-file ./results/scan_20260413
# → ./results/scan_20260413.json
# → ./results/scan_20260413.bbot.ndjson
# → ./results/scan_20260413.xml
# → ./results/scan_20260413.csv
# → ./portex-nuclei/*.yaml
```

If `--output-file` is not set, all formats write to stdout except nuclei-yaml (which writes to `./portex-nuclei/`).

## JSON (`--output json`)

Structured JSON — one object per scan run with a nested array of port results.

```json
{
  "scan_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "target": "10.0.0.1",
  "start_time": "2026-04-13T18:00:00Z",
  "end_time": "2026-04-13T18:02:14Z",
  "ports": [
    {
      "target": "10.0.0.1",
      "port": 443,
      "protocol": "tcp",
      "state": "open",
      "service": {
        "name": "https",
        "version": "nginx/1.25.0",
        "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.25.0\r\n...",
        "cpe": "cpe:/a:nginx:nginx:1.25.0",
        "confidence": 0.97
      },
      "os": {
        "name": "Linux",
        "version": "5.x",
        "accuracy": 0.60
      },
      "llm": {
        "cves": ["CVE-2023-44487"],
        "severity": "high",
        "summary": "...",
        "nuclei_template": "..."
      },
      "ttl": 64,
      "rtt_ms": 1.2,
      "timestamp": "2026-04-13T18:00:41Z"
    }
  ],
  "stats": {
    "total_ports": 1000,
    "open": 3,
    "closed": 941,
    "filtered": 56,
    "duration_s": 134,
    "packets_sent": 1000,
    "packets_received": 1003
  }
}
```

## BBOT NDJSON (`--output bbot`)

One JSON event per line, compatible with bbot's data router and phantom-easm.

### Event types

**OPEN_TCP_PORT**
```json
{
  "type": "OPEN_TCP_PORT",
  "id": "<uuid5>",
  "data": {
    "host": "10.0.0.1",
    "port": 443,
    "proto": "tcp",
    "status": "open",
    "service": "https",
    "version": "nginx/1.25.0",
    "banner": "...",
    "ttl": 64
  },
  "tags": ["portex", "tcp", "open"],
  "module": "portex",
  "scan_id": "<scan_id>",
  "timestamp": "2026-04-13T18:00:41Z"
}
```

**TECHNOLOGY**
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
  "module": "portex"
}
```

**VULNERABILITY** (LLM-enriched only)
```json
{
  "type": "VULNERABILITY",
  "id": "<uuid5>",
  "data": {
    "host": "10.0.0.1",
    "port": 443,
    "severity": "high",
    "cves": ["CVE-2023-44487"],
    "summary": "HTTP/2 Rapid Reset DoS vulnerability in nginx 1.25.0"
  },
  "tags": ["portex", "llm-enriched"],
  "module": "portex"
}
```

Event IDs are deterministic UUID v5 keyed on `(type, host, port)` so the phantom data-router deduplicates across multiple Portex runs.

## nmap XML (`--output xml`)

Compatible with any tool that consumes nmap XML output — Metasploit, Faraday, ShodanHound, etc.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="portex" version="1.0.0" ...>
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="nginx" version="1.25.0"
                 extrainfo="" cpe="cpe:/a:nginx:nginx:1.25.0"/>
      </port>
    </ports>
  </host>
</nmaprun>
```

## CSV (`--output csv`)

One row per open port. Suitable for spreadsheet import.

```
scan_id,target,port,protocol,state,service,version,cpes,cves,severity,ttl,rtt_ms,timestamp
f47ac10b,...,10.0.0.1,443,tcp,open,https,nginx/1.25.0,"cpe:/a:nginx:nginx:1.25.0","CVE-2023-44487",high,64,1.2,2026-04-13T18:00:41Z
```

## Nuclei YAML (`--output nuclei-yaml`)

Generates a ready-to-run nuclei template for each open port with a detected service. Templates are written to the output directory (default: `./portex-nuclei/`).

```yaml
id: portex-10.0.0.1-443-nginx-1.25.0

info:
  name: "nginx 1.25.0 on 10.0.0.1:443"
  author: portex
  severity: high
  tags: portex,nginx,generated
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2023-44487

requests:
  - raw:
      - |
        GET / HTTP/1.1
        Host: 10.0.0.1
        ...
    matchers:
      - type: word
        words:
          - "nginx/1.25.0"
```

Run against the target:
```bash
nuclei -t ./portex-nuclei/ -u https://10.0.0.1
```
