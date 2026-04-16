# AI Layers

Portex runs five AI layers around every probe. Each is independently opt-in.

## Layer 1: RL Probe Optimizer (`--rl`)

**File:** `internal/ai/rl/`

The RL agent observes per-port scan state and selects the best probe strategy for the next attempt.

### State vector (12 features)

| Index | Feature | Range |
|---|---|---|
| 0 | Ratio of filtered ports seen | 0.0–1.0 |
| 1 | Ratio of open ports seen | 0.0–1.0 |
| 2 | Ratio of closed ports seen | 0.0–1.0 |
| 3 | RST storm intensity | 0.0–1.0 |
| 4 | Mean RTT (normalised to 10 s) | 0.0–1.0 |
| 5 | RTT variance | 0.0–1.0 |
| 6 | Attempt count for this port | 0.0–1.0 (capped at 10) |
| 7 | Current timing level T0–T5 | 0.0–1.0 |
| 8 | Current scan mode index | 0.0–1.0 |
| 9 | Packet loss rate | 0.0–1.0 |
| 10 | Target type (host=0, /24=0.5, /16=1.0) | 0.0–1.0 |
| 11 | Hours since epoch mod 24 | 0.0–1.0 |

### Actions (8)

| Index | Effect |
|---|---|
| 0 | No change |
| 1 | Switch to SYN mode |
| 2 | Switch to FIN mode |
| 3 | Switch to UDP mode |
| 4 | Increase timing (slow down) |
| 5 | Decrease timing (speed up) |
| 6 | Randomise source port |
| 7 | Switch to NULL mode |

### Policy

The bundled policy is a heuristic baseline — no training required:
- High filtered ratio → switch mode
- RST storm → slow timing
- Attempt > 3 → switch protocol

Swap in a real ONNX model by replacing `data/models/rl_policy.onnx`. Train with `scripts/train_rl.py` (PPO, stable-baselines3).

### Rewards

| Event | Reward |
|---|---|
| Port open discovered | +1.0 |
| Port filtered | -0.5 |
| RST storm detected | -1.0 |
| Stealth bonus (no log) | +0.2 |

## Layer 2: Payload Mutator (`--mutate`)

**File:** `internal/ai/mutator/`

Mutates the built packet before it is sent without changing its semantic meaning to the target.

| Mutator | File | Effect |
|---|---|---|
| IP fragmentation | `frag.go` | Splits IP payload, sets MF bit |
| TTL fuzzing | `ttl.go` | Randomises TTL ±5 around profile value |
| Urgent pointer | `urgent.go` | Sets URG flag + non-zero urgent pointer |
| Source routing | `srcroute.go` | Adds IP LSRR option with bogus hops |
| Flag combinations | `flagcombo.go` | Randomises rare TCP flag combos |

Mutations are selected probabilistically; `validate.go` checks semantic equivalence before sending.

## Layer 3: Protocol Obfuscation (`--mutate` + auto)

**File:** `internal/ai/protocol/`

The `ProtocolMatrix` selects an alternative transport for the probe based on the RL action.

| Mode | File | Description |
|---|---|---|
| QUIC/HTTP3 | `quic.go` | Encapsulates probe in QUIC UDP datagrams |
| DNS tunnel | `dns_tunnel.go` | Encodes probe payload in DNS TXT queries |
| IPv6 ext-hdr | `ipv6.go` | Adds routing/hop-by-hop extension headers |
| ICMP covert | `icmp.go` | Embeds payload in ICMP echo data field |

Falls back gracefully to standard TCP/UDP if the mode is not applicable (e.g. target is IPv4-only).

## Layer 4: Traffic Mimicry (`--mimic`)

**File:** `internal/ai/mimicry/`

Makes Portex traffic indistinguishable from a normal OS at the packet level.

### Inter-packet timing

Uses a Pareto distribution (heavy-tailed, like real user traffic) for inter-probe delays. Avoids the uniform spacing that flags automated scanners in ML-based IDS.

### OS fingerprint injection

| Component | File | Effect |
|---|---|---|
| TCP window size | `window.go` | Per-OS window sizes (Linux: 29200, Windows: 65535, macOS: 65535) |
| TTL injection | `ttl_inject.go` | TTL values matching target OS family |
| Full OS spoof | `os_spoof.go` | Combines window + TTL + DF bit + MSS option |

### Decoy flood

`decoy.go` fires N concurrent spoofed SYN packets from random global-unicast IPs alongside the real probe. The target sees a crowd of scanners — the real source IP is lost in the noise.

```bash
# 10 decoys per real probe
sudo ./bin/portex scan -t 10.0.0.1 -p 80 --mimic
```

Decoy source IPs are selected from the global unicast space, avoiding RFC1918, loopback, and link-local.

## Layer 5: LLM Enrichment (`--llm`)

**File:** `internal/ai/llm/`

For every open port that has a detected service/version, the LLM enricher queries an LLM with the port result and returns structured intelligence.

Three providers are available via `--llm-provider`:

### Claude (default)

```bash
export ANTHROPIC_API_KEY=sk-ant-...
sudo -E ./bin/portex scan -t 10.0.0.1 -p 443 --service-detect --llm
```

Model: `claude-sonnet-4-6`

### Gemini

```bash
export GEMINI_API_KEY=AIza...
sudo -E ./bin/portex scan -t 10.0.0.1 -p 443 --service-detect --llm --llm-provider gemini
```

Model: `gemini-2.0-flash` (default). Override with `--llm-model gemini-1.5-pro`.
Reads `GEMINI_API_KEY` env var. Uses the `generateContent` REST API — no SDK dependency.

### Ollama

```bash
ollama pull llama3 && ollama serve
sudo ./bin/portex scan -t 10.0.0.1 -p 443 --service-detect --llm --llm-provider ollama
```

### Output per port

```json
{
  "cves": ["CVE-2023-44487", "CVE-2021-41773"],
  "severity": "high",
  "summary": "nginx 1.25.0 is vulnerable to HTTP/2 Rapid Reset (CVE-2023-44487) ...",
  "attack_surface": "Web server, TLS termination, reverse proxy",
  "nuclei_template": "id: portex-nginx-1.25.0-cve-2023-44487\n..."
}
```

### Nuclei template generation

With `--output nuclei-yaml`, each LLM enrichment result is also written as a standalone nuclei YAML template file in the output directory:

```bash
sudo ./bin/portex scan -t 10.0.0.1 -p top100 --service-detect --llm \
  --output nuclei-yaml --output-file ./results/target
# → ./portex-nuclei/portex-10.0.0.1-443-nginx.yaml
```
