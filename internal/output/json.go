package output

import (
	"encoding/json"
	"io"
	"sync"
	"time"

	"github.com/m4rvxpn/portex/internal/scanner"
)

// jsonScanResult is the JSON serialisation envelope for a complete scan.
type jsonScanResult struct {
	ScanID     string               `json:"scan_id"`
	SessionID  string               `json:"session_id"`
	StartTime  time.Time            `json:"start_time"`
	EndTime    time.Time            `json:"end_time"`
	Targets    []string             `json:"targets"`
	TotalPorts int                  `json:"total_ports"`
	OpenPorts  int                  `json:"open_ports"`
	Ports      []scanner.PortResult `json:"ports"`
	Stats      scanner.ScanStats    `json:"stats"`
}

// JSONWriter writes scan results as formatted JSON.
type JSONWriter struct {
	w       io.Writer
	encoder *json.Encoder
	ports   []scanner.PortResult
	mu      sync.Mutex
}

// NewJSONWriter returns a new JSONWriter that writes to w.
func NewJSONWriter(w io.Writer) *JSONWriter {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return &JSONWriter{
		w:       w,
		encoder: enc,
	}
}

// WritePort buffers a port result for inclusion in the final JSON document.
func (j *JSONWriter) WritePort(r scanner.PortResult) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.ports = append(j.ports, r)
	return nil
}

// WriteResult writes the full scan result as a single JSON object.
func (j *JSONWriter) WriteResult(r *scanner.ScanResult) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	out := jsonScanResult{
		ScanID:     r.ScanID,
		SessionID:  r.SessionID,
		StartTime:  r.StartTime,
		EndTime:    r.EndTime,
		Targets:    r.Targets,
		TotalPorts: r.TotalPorts,
		OpenPorts:  r.OpenPorts,
		Ports:      r.Ports,
		Stats:      r.Stats,
	}

	// Prefer the buffered streaming ports if WritePort was used.
	if len(j.ports) > 0 && len(r.Ports) == 0 {
		out.Ports = j.ports
		out.TotalPorts = len(j.ports)
		for _, p := range j.ports {
			if p.State == scanner.StateOpen {
				out.OpenPorts++
			}
		}
	}

	return j.encoder.Encode(out)
}

// Close is a no-op for JSONWriter; all data is written by WriteResult.
func (j *JSONWriter) Close() error {
	return nil
}
