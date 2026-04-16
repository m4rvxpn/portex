# Firewall Lab

A self-contained Docker Compose lab for testing all five Portex AI layers against live AI/ML firewalls.

## Architecture

```
PORTEX Scanner (host)
      │
      ├─ :8081  nginx-waf (open-appsec ML)     ← Layer 2 mutation testing
      ├─ :8082  DVWA                            ← direct target
      ├─ :3001  Juice Shop                      ← direct target
      ├─ :8083  SafeLine tengine                ← Layer 3 protocol obfuscation
      ├─ :9443  SafeLine admin UI
      └─ internal  CrowdSec                     ← Layer 1 RL probe detection
```

## Stack

| Container | Image | Purpose |
|---|---|---|
| dvwa | `vulnerables/web-dvwa` | Vulnerable web target |
| juiceshop | `bkimminich/juice-shop` | OWASP vulnerable target |
| crowdsec | `crowdsecurity/crowdsec` | Layer 1: behavioral baselining |
| open-appsec-agent | `ghcr.io/openappsec/agent` | Layer 2: ML WAF engine |
| nginx-waf | `ghcr.io/openappsec/nginx-attachment` | Layer 2: WAF proxy on :8081 |
| safeline-tengine | `chaitin/safeline-tengine` | Layer 3: semantic analysis proxy |
| safeline-mgt | `chaitin/safeline-mgt` | SafeLine management UI on :9443 |
| safeline-fvm | `chaitin/safeline-fvm` | SafeLine ML model service |
| safeline-luigi | `chaitin/safeline-luigi` | SafeLine rule engine |
| safeline-pg | `postgres:15-alpine` | SafeLine database |

## Setup

```bash
# Clone or build Portex first
make build

# Start the lab
cd ~/portex-lab
docker compose up -d

# Check all containers
docker compose ps
```

First-run note: visit `https://localhost:9443` and complete the SafeLine admin setup before `safeline-luigi` stabilises.

## Test Matrix

### Layer 1 — RL Probes vs CrowdSec

CrowdSec monitors nginx access logs and bans IPs that show scanning patterns.

```bash
# Run RL-adapted stealth scan
sudo ./bin/portex scan -t 127.0.0.1 -p 8081 --mode stealth --rl --timing 3 --output json -v

# Watch CrowdSec decisions in real time
watch -n3 docker exec crowdsec cscli decisions list

# Check what scenarios triggered
docker exec crowdsec cscli alerts list
```

**What to measure:** How many probe rounds before CrowdSec bans the source IP. With `--rl` enabled the agent adapts its timing and probe type based on observed RST/filtered ratios.

### Layer 2 — Payload Mutation vs open-appsec ML WAF

open-appsec uses a zero-signature ML engine that scores request payloads. Mutated packets change packet structure without altering semantic intent.

```bash
# Service detect with mutation enabled — targets WAF at :8081
sudo ./bin/portex scan -t 127.0.0.1 -p 8081 --mode syn --mutate --service-detect --output json

# Monitor open-appsec block decisions
tail -f ~/portex-lab/logs/nano_agent.log 2>/dev/null | jq '.severity, .attack_type, .source_ip'

# Count blocked vs allowed in nginx log
awk '{print $9}' ~/portex-lab/logs/access.log | sort | uniq -c
```

**What to measure:** Percentage of mutated probes that receive a `200` vs `403`/`400` from open-appsec.

### Layer 3 — Protocol Obfuscation vs SafeLine

SafeLine uses semantic analysis to detect attack patterns regardless of protocol framing.

```bash
# SCTP + NULL + FIN probes through SafeLine tengine
sudo ./bin/portex scan -t 127.0.0.1 -p 8083 --mode sctp --output json
sudo ./bin/portex scan -t 127.0.0.1 -p 8083 --mode null --output json
sudo ./bin/portex scan -t 127.0.0.1 -p 8083 --mode stealth --mutate --output json

# SafeLine detection log
docker logs safeline-tengine 2>&1 | grep -i "block\|detect\|attack" | tail -20
```

**What to measure:** Which non-standard scan modes SafeLine detects vs lets through.

### Layer 4 — Traffic Mimicry vs CrowdSec Behavioral

Traffic mimicry injects realistic OS fingerprints and inter-packet timing distributions to blend with normal user traffic.

```bash
# Mimicry + decoy flood — CrowdSec sees traffic from many IPs
sudo ./bin/portex scan -t 127.0.0.1 -p 8081 --mode syn --mimic --timing 2 --output json

# How many distinct source IPs did CrowdSec see?
docker exec crowdsec cscli decisions list | wc -l
```

**What to measure:** Whether CrowdSec fires on the real source IP vs decoy IPs only.

### Layer 5 — LLM Enrichment on discovered ports

After the scan, the LLM queries CVEs and generates nuclei templates for each open port.

```bash
# Scan DVWA, enrich with Gemini, generate nuclei templates
export GEMINI_API_KEY=AIza...
sudo -E ./bin/portex scan -t 127.0.0.1 -p 8082 \
  --mode connect --service-detect \
  --llm --llm-provider gemini \
  --output json,nuclei-yaml \
  --output-file ./results/dvwa

# Run generated templates against target
nuclei -t ./portex-nuclei/ -u http://localhost:8082
```

## Monitoring

```bash
# All logs streaming
docker compose logs -f

# CrowdSec live decisions
watch -n5 docker exec crowdsec cscli decisions list

# open-appsec block log
tail -f ~/portex-lab/logs/nano_agent.log | jq .

# SafeLine events
docker logs -f safeline-tengine

# Stop entire lab
docker compose down
```

## Resetting

```bash
# Full reset — removes all data and decisions
docker compose down -v
rm -rf ~/portex-lab/safeline/resources/postgres \
       ~/portex-lab/safeline/resources/mgt \
       ~/portex-lab/crowdsec/data \
       ~/portex-lab/logs/*
docker compose up -d
```
