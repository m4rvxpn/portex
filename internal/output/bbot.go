package output

import (
	"encoding/json"
	"io"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/m4rvxpn/portex/internal/scanner"
)

// BBOTWriter emits BBOT-compatible NDJSON events.
// Event types: OPEN_TCP_PORT, TECHNOLOGY, VULNERABILITY
type BBOTWriter struct {
	w      io.Writer
	mu     sync.Mutex
	scanID string
}

// BBOTEvent is a single BBOT NDJSON event.
type BBOTEvent struct {
	Type      string      `json:"type"`
	ID        string      `json:"id"`
	Data      interface{} `json:"data"`
	Tags      []string    `json:"tags"`
	Module    string      `json:"module"`
	Source    string      `json:"source"`
	Timestamp string      `json:"timestamp"`
	ScanID    string      `json:"scan_id"`
}

// OpenPortData is the data payload for an OPEN_TCP_PORT event.
type OpenPortData struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Status  string `json:"status"`
	Service string `json:"service,omitempty"`
	Version string `json:"version,omitempty"`
	Banner  string `json:"banner,omitempty"`
	TTL     uint8  `json:"ttl,omitempty"`
}

// TechnologyData is the data payload for a TECHNOLOGY event.
type TechnologyData struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Tech    string `json:"tech"`
	Version string `json:"version,omitempty"`
	CPE     string `json:"cpe,omitempty"`
}

// VulnerabilityData is the data payload for a VULNERABILITY event.
type VulnerabilityData struct {
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	Severity string   `json:"severity"`
	CVEs     []string `json:"cves,omitempty"`
	Summary  string   `json:"summary"`
}

// NewBBOTWriter creates a new BBOTWriter writing NDJSON to w.
func NewBBOTWriter(w io.Writer, scanID string) *BBOTWriter {
	return &BBOTWriter{w: w, scanID: scanID}
}

// bbotEventID generates a deterministic UUID v5 for (type, host, port).
func bbotEventID(evType, host string, port int) string {
	key := evType + ":" + host + ":" + strconv.Itoa(port)
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte(key)).String()
}

// emit serialises and writes a single BBOTEvent as a newline-terminated JSON object.
func (b *BBOTWriter) emit(ev BBOTEvent) error {
	data, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = b.w.Write(data)
	return err
}

// WritePort emits OPEN_TCP_PORT (always), plus optional TECHNOLOGY and
// VULNERABILITY events when the relevant enrichment data is present.
func (b *BBOTWriter) WritePort(r scanner.PortResult) error {
	if r.State != scanner.StateOpen {
		return nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	ts := r.Timestamp.UTC().Format(time.RFC3339)

	portData := OpenPortData{
		Host:   r.Target,
		Port:   r.Port,
		Proto:  r.Protocol,
		Status: string(r.State),
		TTL:    r.TTL,
	}
	if r.Service != nil {
		portData.Service = r.Service.Service
		portData.Version = r.Service.Version
		portData.Banner = r.Service.Banner
	}

	if err := b.emit(BBOTEvent{
		Type:      "OPEN_TCP_PORT",
		ID:        bbotEventID("OPEN_TCP_PORT", r.Target, r.Port),
		Data:      portData,
		Tags:      []string{"portex", "portscan"},
		Module:    "portex",
		Source:    "portex",
		Timestamp: ts,
		ScanID:    b.scanID,
	}); err != nil {
		return err
	}

	// Emit TECHNOLOGY event if service information is available.
	if r.Service != nil && r.Service.Service != "" {
		techData := TechnologyData{
			Host:    r.Target,
			Port:    r.Port,
			Tech:    r.Service.Product,
			Version: r.Service.Version,
			CPE:     r.Service.CPE,
		}
		if techData.Tech == "" {
			techData.Tech = r.Service.Service
		}
		if err := b.emit(BBOTEvent{
			Type:      "TECHNOLOGY",
			ID:        bbotEventID("TECHNOLOGY", r.Target, r.Port),
			Data:      techData,
			Tags:      []string{"portex", "service-detect"},
			Module:    "portex",
			Source:    "portex",
			Timestamp: ts,
			ScanID:    b.scanID,
		}); err != nil {
			return err
		}
	}

	// Emit VULNERABILITY event if LLM enrichment found CVEs.
	if r.LLMEnrich != nil && len(r.LLMEnrich.CVEs) > 0 {
		severity := "medium"
		if len(r.LLMEnrich.CVEs) > 5 {
			severity = "high"
		}
		vulnData := VulnerabilityData{
			Host:     r.Target,
			Port:     r.Port,
			Severity: severity,
			CVEs:     r.LLMEnrich.CVEs,
			Summary:  r.LLMEnrich.Summary,
		}
		if err := b.emit(BBOTEvent{
			Type:      "VULNERABILITY",
			ID:        bbotEventID("VULNERABILITY", r.Target, r.Port),
			Data:      vulnData,
			Tags:      []string{"portex", "llm-enrich"},
			Module:    "portex",
			Source:    "portex",
			Timestamp: ts,
			ScanID:    b.scanID,
		}); err != nil {
			return err
		}
	}

	return nil
}

// WriteResult is a no-op for BBOTWriter because events are streamed via WritePort.
func (b *BBOTWriter) WriteResult(_ *scanner.ScanResult) error {
	return nil
}

// Close is a no-op for BBOTWriter.
func (b *BBOTWriter) Close() error {
	return nil
}
