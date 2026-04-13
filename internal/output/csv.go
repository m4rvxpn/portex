package output

import (
	"encoding/csv"
	"io"
	"strconv"
	"sync"

	"github.com/m4rvxpn/portex/internal/scanner"
)

// CSV columns: target,port,protocol,state,reason,rtt_ms,ttl,service,version,banner
var csvHeader = []string{
	"target", "port", "protocol", "state", "reason",
	"rtt_ms", "ttl", "service", "version", "banner",
}

// CSVWriter writes results as CSV with a header row.
type CSVWriter struct {
	w      io.Writer
	csv    *csv.Writer
	mu     sync.Mutex
	header bool
}

// NewCSVWriter returns a new CSVWriter that writes to w.
func NewCSVWriter(w io.Writer) *CSVWriter {
	return &CSVWriter{
		w:   w,
		csv: csv.NewWriter(w),
	}
}

// WritePort writes a single port result as a CSV row.
// The header row is written once before the first data row.
func (c *CSVWriter) WritePort(r scanner.PortResult) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.header {
		if err := c.csv.Write(csvHeader); err != nil {
			return err
		}
		c.header = true
	}

	service := ""
	version := ""
	banner := ""
	if r.Service != nil {
		service = r.Service.Service
		version = r.Service.Version
		banner = r.Service.Banner
	}

	rttMs := strconv.FormatFloat(float64(r.RTT.Milliseconds()), 'f', 3, 64)

	row := []string{
		r.Target,
		strconv.Itoa(r.Port),
		r.Protocol,
		string(r.State),
		r.Reason,
		rttMs,
		strconv.Itoa(int(r.TTL)),
		service,
		version,
		banner,
	}

	return c.csv.Write(row)
}

// WriteResult writes all ports from a complete ScanResult.
// If WritePort was already used for streaming, this may write duplicates;
// callers should use one pattern or the other.
func (c *CSVWriter) WriteResult(r *scanner.ScanResult) error {
	for _, p := range r.Ports {
		if err := c.WritePort(p); err != nil {
			return err
		}
	}
	return nil
}

// Close flushes any buffered CSV data.
func (c *CSVWriter) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.csv.Flush()
	return c.csv.Error()
}
