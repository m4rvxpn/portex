# REST API

Start the server:

```bash
sudo ./bin/portex serve --bind 0.0.0.0:8080 --api-key $(openssl rand -hex 32)
```

All endpoints require `Authorization: Bearer <api-key>` unless the key is empty.

## Endpoints

### `POST /v1/scan` — Start async scan

Returns immediately with a `scan_id`. Use `GET /v1/scan/:id` to poll status.

**Request**
```json
{
  "targets": ["10.0.0.1", "10.0.0.0/24"],
  "ports": "top1000",
  "mode": "syn",
  "timing": 3,
  "goroutines": 5000,
  "enable_rl": false,
  "enable_mutator": false,
  "enable_mimicry": false,
  "enable_llm": false,
  "llm_provider": "claude",
  "service_detect": true,
  "os_detect": false,
  "script_scan": false,
  "scripts": [],
  "output_formats": ["json", "bbot"],
  "output_file": "",
  "proxy": "",
  "session_id": "phantom-abc123"
}
```

**Response 202**
```json
{
  "scan_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "state": "running",
  "created_at": "2026-04-13T18:00:00Z"
}
```

### `GET /v1/scan/:id` — Scan status

```json
{
  "scan_id": "f47ac10b-...",
  "state": "running",
  "progress": {
    "ports_scanned": 412,
    "ports_total": 1000,
    "open_ports": 2
  },
  "created_at": "2026-04-13T18:00:00Z",
  "updated_at": "2026-04-13T18:00:41Z"
}
```

States: `running` | `completed` | `failed` | `cancelled`

### `GET /v1/scan/:id/results` — Fetch results

Returns a JSON array of `PortResult` objects for a completed scan.

Add `Accept: text/event-stream` for Server-Sent Events (SSE) streaming — results arrive as they are discovered during a running scan.

**SSE example**
```bash
curl -H "Authorization: Bearer $KEY" \
     -H "Accept: text/event-stream" \
     http://localhost:8080/v1/scan/f47ac10b-.../results
```

Each SSE event is a JSON-encoded `PortResult`.

### `DELETE /v1/scan/:id` — Cancel scan

```json
{"scan_id": "f47ac10b-...", "state": "cancelled"}
```

### `POST /v1/scan/sync` — Synchronous scan

Runs the scan and returns results in a single HTTP response. Times out after 60 seconds.

**Response 200**
```json
{
  "scan_id": "...",
  "ports": [...],
  "stats": {...}
}
```

### `GET /v1/health` — Liveness

```json
{"status": "ok", "version": "1.0.0"}
```

### `GET /metrics` — Prometheus

Standard Prometheus text format. Exposes:

| Metric | Type | Description |
|---|---|---|
| `portex_scans_total` | Counter | Total scans started |
| `portex_ports_scanned_total` | Counter | Total port probes sent |
| `portex_open_ports_total` | Counter | Total open ports discovered |
| `portex_scan_duration_seconds` | Histogram | Scan duration distribution |
| `portex_goroutines_active` | Gauge | Active worker goroutines |

## Authentication

Pass the API key in the `Authorization` header:

```bash
curl -H "Authorization: Bearer mykey" http://localhost:8080/v1/health
```

If `--api-key` is not set, the server runs unauthenticated (development only).

## Example Workflow

```bash
# Start server
sudo ./bin/portex serve --bind 127.0.0.1:8080 --api-key secret &

# Submit scan
SCAN_ID=$(curl -s -X POST http://127.0.0.1:8080/v1/scan \
  -H "Authorization: Bearer secret" \
  -H "Content-Type: application/json" \
  -d '{"targets":["127.0.0.1"],"ports":"22,80,443","mode":"syn"}' \
  | jq -r .scan_id)

echo "Scan ID: $SCAN_ID"

# Poll until complete
while true; do
  STATE=$(curl -s http://127.0.0.1:8080/v1/scan/$SCAN_ID \
    -H "Authorization: Bearer secret" | jq -r .state)
  echo "State: $STATE"
  [ "$STATE" = "completed" ] && break
  sleep 2
done

# Fetch results
curl -s http://127.0.0.1:8080/v1/scan/$SCAN_ID/results \
  -H "Authorization: Bearer secret" | jq .
```
