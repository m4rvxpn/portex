# Architecture

## Overview

Portex is structured as a layered pipeline. The CLI or REST API creates a `Config`, hands it to `portex.PortexScanner`, which orchestrates the scan engine, packet layer, AI layers, and output writers.

```
cmd/portex/main.go
    └── internal/cli          (cobra commands, flag parsing)
            └── internal/portex/scanner.go   (PortexScanner — top-level orchestrator)
                    ├── internal/scanner/engine.go   (goroutine pool, probe dispatch)
                    ├── internal/packet/             (raw socket, packet builder, libpcap)
                    ├── internal/ai/                 (RL, mutator, protocol, mimicry, LLM)
                    ├── internal/service/            (banner grab, nmap-service-probes)
                    ├── internal/os/                 (OS fingerprinting)
                    ├── internal/script/             (gopher-lua NSE engine)
                    └── internal/output/             (JSON, BBOT, XML, CSV, nuclei)
```

## Concurrency Model

```
PortexScanner.Scan()
    │
    ├─ Capturer goroutine  (single, reads libpcap frames)
    │       └─ dispatches responses via sync.Map[CorrelationKey → chan []byte]
    │
    └─ Engine goroutine pool  (N=5000 workers, default)
            │  reads from chan Probe (buffered 10×N)
            ├─ worker 0 → AI pipeline → RawSocket.Write → wait on response chan
            ├─ worker 1 → ...
            └─ worker N → ...
                    │
                    └─ results → chan PortResult → output writers
```

**Key design decisions:**
- Workers never block on each other. Each probe gets its own response channel registered in the sync.Map before the packet is sent.
- The single Capturer goroutine avoids any synchronization on the pcap handle.
- `sync.Pool` of `gopacket.SerializeBuffer` means zero heap allocation per packet.
- The token-bucket rate limiter (`internal/scanner/ratelimit.go`) uses EWMA over observed RTT to adaptively throttle before the kernel queue backs up.

## Package Dependency Graph

```
cmd/portex
    └── internal/cli
            └── internal/portex        ← top-level orchestrator (avoids circular import)
                    ├── internal/scanner       (engine, result types, probe, ratelimit)
                    ├── internal/packet        (rawsock, builder, capture, scan types)
                    ├── internal/service       (probes, banner, detect)
                    ├── internal/os            (database, fingerprint)
                    ├── internal/script        (lua VM pool)
                    ├── internal/ai/rl
                    ├── internal/ai/mutator
                    ├── internal/ai/protocol
                    ├── internal/ai/mimicry
                    ├── internal/ai/llm
                    ├── internal/output
                    ├── internal/proxy
                    └── internal/data          (go:embed nmap files + rl_policy.onnx)
```

`internal/packet` imports `internal/scanner` for `PortState` constants. To avoid a cycle, `PortexScanner` lives in its own `internal/portex` package rather than in `internal/scanner`.

## Packet Lifecycle

1. `Engine` dequeues a `Probe{Target, Port, SrcPort, Mode, ...}`.
2. **Layer 1** — `rl.GetAction(state)` may override Mode, TTL, SrcPort.
3. `PacketBuilder.BuildTCP(...)` (or UDP/SCTP) from `sync.Pool` buffer.
4. **Layer 2** — `mutator.Mutate(pkt)` may fragment, pad, or set urgent pointer.
5. **Layer 3** — `protocol.Select(action)` may tunnel via DNS/QUIC.
6. **Layer 4** — `mimicry.InjectTiming()` sleeps per Pareto distribution; `SpoofOS()` sets window/TTL; `Flood()` sends concurrent decoys from spoofed IPs.
7. `RawSocket.Write(pkt)` — AF_PACKET/SOCK_RAW send.
8. `Capturer` reads pcap frame, extracts `CorrelationKey(srcIP, dstIP, srcPort, dstPort)`, looks up registered channel, sends payload.
9. Worker receives response, calls `determineState(flags)`, returns `PortResult`.
10. **Layer 5** — if port is open, `llm.Enrich(result)` returns CVEs + nuclei template.
11. `OutputWriter.WritePort(result)` fans out to all configured formats.

## Embedded Data Files

All data files are compiled into the binary via `go:embed` in `internal/data/data.go`:

| Constant | File | Size |
|---|---|---|
| `NmapServiceProbes` | `data/nmap-service-probes` | ~700 KB |
| `NmapOSDB` | `data/nmap-os-db` | ~4 MB |
| `RLPolicyONNX` | `data/models/rl_policy.onnx` | placeholder (swap real model) |

## Timing Profiles

| Level | Name | Min RTT | Max RTT | Parallelism | Use case |
|---|---|---|---|---|---|
| T0 | Paranoid | 5 min | 5 min | 1 | IDS-safe, slowest |
| T1 | Sneaky | 15 s | 30 s | 1 | Stealth recon |
| T2 | Polite | 400 ms | 1 s | 10 | Low bandwidth |
| T3 | Normal | 100 ms | 200 ms | 100 | Default |
| T4 | Aggressive | 10 ms | 50 ms | 1000 | Fast LAN scan |
| T5 | Insane | 5 ms | 10 ms | 5000 | Max speed, noisy |

## Response Correlation

The `CorrelationKey` function produces a deterministic string:

```go
func CorrelationKey(srcIP, dstIP string, srcPort, dstPort uint16) string {
    return fmt.Sprintf("%s:%d->%s:%d", srcIP, srcPort, dstIP, dstPort)
}
```

The Capturer uses the *source IP/port of the incoming packet* (which is the target's IP and target port) as `srcIP:srcPort`, and our IP/srcPort as `dstIP:dstPort`. Scan type handlers register the inverse: `CorrelationKey(target, ourIP, targetPort, ourSrcPort)`.
