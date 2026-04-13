# Scan Modes

All raw-socket modes require root or `CAP_NET_RAW`. TCP connect works unprivileged.

## SYN Scan (`--mode syn`)

The default and fastest mode. Sends a TCP SYN packet and waits for the response without completing the handshake.

| Response | Port state |
|---|---|
| SYN+ACK | open |
| RST | closed |
| No response (timeout) | filtered |
| ICMP port unreachable | filtered |

```bash
sudo ./bin/portex scan -t 10.0.0.1 -p top1000 --mode syn
```

The kernel automatically sends a RST when the SYN+ACK arrives (because Portex never completes the handshake), so no connection state is held.

## TCP Connect (`--mode connect`)

Uses the OS `connect()` syscall. No raw socket needed; works in containers and without root. Slower than SYN because the full handshake runs.

```bash
./bin/portex scan -t 10.0.0.1 -p 80,443 --mode connect
```

## ACK Scan (`--mode ack`)

Sends a TCP ACK to a port. Useful for mapping firewall rules rather than discovering open ports.

| Response | Meaning |
|---|---|
| RST | port is unfiltered (firewall passes ACK) |
| No response / ICMP | port is filtered |

```bash
sudo ./bin/portex scan -t 10.0.0.1 -p 1-1024 --mode ack
```

## FIN Scan (`--mode fin`)

Sends a TCP FIN packet. Many simple packet filters allow FIN through because they only block SYN.

| Response | State |
|---|---|
| No response | open or filtered |
| RST | closed |

```bash
sudo ./bin/portex scan -t 10.0.0.1 -p top100 --mode fin
```

## XMAS Scan (`--mode xmas`)

Sets FIN, PSH, and URG flags simultaneously. Works like FIN on RFC-compliant stacks. Windows systems return RST for all ports regardless of state.

```bash
sudo ./bin/portex scan -t 10.0.0.1 -p top100 --mode xmas
```

## NULL Scan (`--mode null`)

Sends a TCP packet with no flags. Same interpretation as FIN and XMAS.

```bash
sudo ./bin/portex scan -t 10.0.0.1 -p top100 --mode null
```

## Window Scan (`--mode window`)

Like ACK scan but examines the RST window size. Some operating systems report non-zero window size for open ports, zero for closed — a side channel for state discovery without a three-way handshake.

```bash
sudo ./bin/portex scan -t 10.0.0.1 -p 80,443,8080 --mode window
```

## Maimon Scan (`--mode maimon`)

FIN+ACK probe. Derives from Uriel Maimon's 1996 paper. BSD-derived systems drop the packet for open ports; others send RST.

```bash
sudo ./bin/portex scan -t 10.0.0.1 -p top100 --mode maimon
```

## UDP Scan (`--mode udp`)

Sends a UDP datagram to each port (with service-appropriate payload when `--service-detect` is enabled). Requires more time because UDP is connectionless.

| Response | State |
|---|---|
| Any UDP response | open |
| ICMP port unreachable (type 3, code 3) | closed |
| Other ICMP unreachable | filtered |
| No response | open or filtered |

Default rate: 1000 PPS to avoid flooding the ICMP rate limiter on the target.

```bash
sudo ./bin/portex scan -t 10.0.0.1 -p 53,67,123,161 --mode udp --service-detect
```

## SCTP INIT Scan (`--mode sctp`)

Sends an SCTP INIT chunk. SCTP is used in VoIP, SS7 gateways, and some network appliances.

| Response | State |
|---|---|
| INIT-ACK | open |
| ABORT | closed |
| No response / ICMP | filtered |

```bash
sudo ./bin/portex scan -t 10.0.0.1 -p 2905,9900 --mode sctp
```

## IP Protocol Scan (`--mode ipproto`)

Cycles through IP protocol numbers (1=ICMP, 6=TCP, 17=UDP, ...) to discover which protocols the host supports. Reports each supported protocol number as an "open port".

```bash
sudo ./bin/portex scan -t 10.0.0.1 -p all --mode ipproto
```

## Idle / Zombie Scan (`--mode idle`)

A completely blind scan. Portex spoof-SYNs from a zombie host's IP and measures the zombie's IPID to infer the target port state. The scanner's real IP never appears in traffic to the target.

**Requires a zombie host** with a predictable (incrementing) IPID sequence and no active traffic. Older Windows systems, embedded devices, and printers often work.

```bash
sudo ./bin/portex scan -t 10.0.0.5 -p 22,80,443 --mode idle --zombie 10.0.0.3:80
```

How it works:
1. Sample zombie IPID (baseline)
2. Spoof SYN to target from zombie's IP
3. Sample zombie IPID again
4. IPID+2 → target port sent RST to zombie → port is open
5. IPID+1 → target RST'd our spoofed SYN directly → port is closed/filtered

## Stealth Mode (`--mode stealth`)

Meta-mode that delegates mode selection to the RL agent. The agent picks the scan type, timing, TTL, and source port based on observed target behaviour (RTT variance, RST storms, filtered rates). Falls back to SYN if `--rl` is not enabled.

```bash
sudo ./bin/portex scan -t 10.0.0.1 -p top1000 --mode stealth --rl --mutate --mimic
```
