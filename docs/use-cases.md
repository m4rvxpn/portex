# Use Cases

## Red Team / Penetration Testing

### Initial reconnaissance

Fast, quiet initial recon across an engagement's full IP scope. SYN scan at T3 finds open ports; service detection identifies attack surface in a single pass.

```bash
# Scope: 10.0.0.0/16, top ports, service detection
sudo ./bin/portex scan \
  -t 10.0.0.0/16 \
  -p top1000 \
  --mode syn \
  --timing 3 \
  --service-detect \
  --output json,csv \
  --output-file ./recon/initial
```

### Evading IDS/IPS

When a target has stateful inspection or an ML-based IDS:

```bash
# Slow, fragmented, OS-spoofed, decoy-flooded
sudo ./bin/portex scan \
  -t 10.0.0.1 \
  -p top100 \
  --mode stealth \
  --timing 1 \
  --rl --mutate --mimic \
  --output json
```

The RL agent adapts its probe strategy in real time based on the observed filtered/RST ratio, and the decoy flood makes attribution difficult.

### Firewall rule mapping

ACK scan discovers which ports are unfiltered (no stateful firewall) vs filtered (firewall blocks ACK packets that aren't part of an established session).

```bash
sudo ./bin/portex scan -t 10.0.0.1 -p 1-65535 --mode ack --timing 4
```

### Blind scan via zombie

When the red team's IP must not appear in target logs:

```bash
# Find a zombie (low-traffic host with predictable IPID)
sudo ./bin/portex scan -t 10.0.0.3 -p 1-100 --mode ipid-probe

# Scan target through zombie
sudo ./bin/portex scan -t 10.0.0.5 -p 22,80,443,3389 --mode idle --zombie 10.0.0.3:80
```

### Automated nuclei templates

From open ports to ready-to-run exploit templates in one command:

```bash
sudo ./bin/portex scan \
  -t 10.0.0.0/24 \
  -p top1000 \
  --mode syn \
  --service-detect \
  --llm \
  --output nuclei-yaml \
  --output-file ./recon/target

# Run generated templates
nuclei -t ./portex-nuclei/ -l ./recon/live_hosts.txt
```

## Bug Bounty

### Large CIDR asset discovery

Bug bounty scopes often include large IP ranges. Portex's 5000-goroutine default tears through a /16 in minutes.

```bash
# Discover all open ports across scope
sudo ./bin/portex scan \
  -t @scope_ips.txt \
  -p top1000 \
  --mode syn \
  --timing 4 \
  --service-detect \
  --output json,bbot \
  --output-file ./bounty/$(date +%Y%m%d)
```

### Targeted deep scan on interesting hosts

After finding live hosts, run a full port + LLM enrichment pass on high-value targets.

```bash
sudo ./bin/portex scan \
  -t 203.0.113.42 \
  -p all \
  --mode syn \
  --service-detect \
  --os-detect \
  --script-scan \
  --llm \
  --output json,nuclei-yaml
```

### CVE triage

The LLM enrichment immediately flags known CVEs for each service version found. Useful for triaging a large scope quickly before manual verification.

## Enterprise Asset Inventory

### Scheduled network audit

```bash
# Weekly full-network scan, BBOT output for SIEM
sudo ./bin/portex scan \
  -t 10.0.0.0/8 \
  -p top1000 \
  --mode connect \
  --timing 2 \
  --service-detect \
  --output bbot,json \
  --output-file /var/log/portex/audit_$(date +%Y%m%d) \
  --session-id audit-weekly
```

`--mode connect` avoids raw socket requirements for scheduled jobs running without root (use `setcap` or a service account with `CAP_NET_RAW`).

### Change detection

Compare two JSON outputs to find new/closed ports:

```bash
jq -r '.ports[] | "\(.target):\(.port) \(.state)"' before.json > before.txt
jq -r '.ports[] | "\(.target):\(.port) \(.state)"' after.json  > after.txt
diff before.txt after.txt
```

### REST API for CMDB integration

```bash
# Start API server
sudo ./bin/portex serve --bind 127.0.0.1:8080 --api-key $KEY

# Trigger scan from CMDB workflow
curl -X POST http://127.0.0.1:8080/v1/scan \
  -H "Authorization: Bearer $KEY" \
  -d '{"targets":["10.0.0.1"],"ports":"top1000","mode":"syn","service_detect":true}'
```

## EASM / External Attack Surface Management

### phantom-easm integration

Portex is the scanning engine for phantom-easm. Run it via bbot's phantom module config or standalone with BBOT output:

```bash
sudo ./bin/portex scan \
  -t @external_assets.txt \
  -p top1000 \
  --mode stealth \
  --rl --mutate --mimic \
  --llm \
  --output bbot \
  --session-id $PHANTOM_SESSION_ID \
  | tee /var/log/phantom/portex.ndjson
```

The BBOT NDJSON stream feeds into the phantom data-router, which enriches results with passive DNS, cert transparency, and Shodan data from other modules.

### Continuous monitoring

Wrap Portex in a cron or systemd timer for continuous external surface monitoring:

```bash
# /etc/cron.d/portex-monitor
0 */6 * * * root /usr/local/bin/portex scan \
  -t @/etc/portex/monitor_targets.txt \
  -p top100 \
  --mode syn \
  --service-detect \
  --output bbot,json \
  --output-file /var/log/portex/monitor_$(date +\%Y\%m\%d_\%H\%M)
```

## CI/CD Pipeline Integration

### Pre-deployment security gate

Run a connect scan against a staging environment in CI. Fail the build if unexpected ports are open.

```bash
# In CI (no root needed with connect mode)
./bin/portex scan -t staging.internal -p 1-65535 --mode connect --output json \
  --output-file /tmp/staging_scan

# Assert no unexpected ports
python3 -c "
import json, sys
result = json.load(open('/tmp/staging_scan.json'))
expected = {22, 443}
found = {p['port'] for p in result['ports'] if p['state'] == 'open'}
unexpected = found - expected
if unexpected:
    print(f'FAIL: unexpected open ports: {unexpected}')
    sys.exit(1)
print('PASS: only expected ports open')
"
```

## UDP Service Discovery

UDP services (DNS, SNMP, TFTP, NTP) are often overlooked.

```bash
# Common UDP services
sudo ./bin/portex scan \
  -t 10.0.0.0/24 \
  -p 53,67,68,69,123,137,138,161,162,500,514,1194,4500 \
  --mode udp \
  --service-detect \
  --timing 3 \
  --output json
```
