// Package output provides streaming output writers for Portex scan results.
// Supported formats: json, bbot, xml, csv, nuclei-yaml.
package output

import (
	"fmt"
	"io"

	"github.com/m4rvxpn/portex/internal/scanner"
)

// Writer is the interface all output formats implement.
type Writer interface {
	// WritePort writes a single port result as it arrives (streaming).
	WritePort(r scanner.PortResult) error
	// WriteResult writes the final complete scan result.
	WriteResult(r *scanner.ScanResult) error
	// Close flushes and closes the writer.
	Close() error
}

// NewWriter creates an output writer for the given format.
// format: "json", "bbot", "xml", "csv", "nuclei-yaml"
// w: destination io.Writer (typically os.Stdout or a file)
// scanID: unique identifier for this scan session
func NewWriter(format string, w io.Writer, scanID string) (Writer, error) {
	switch format {
	case "json":
		return NewJSONWriter(w), nil
	case "bbot":
		return NewBBOTWriter(w, scanID), nil
	case "xml":
		return NewNmapXMLWriter(w), nil
	case "csv":
		return NewCSVWriter(w), nil
	case "nuclei-yaml":
		// nuclei-yaml writes files to a directory; caller passes a dir path via scanID.
		return NewNucleiYAMLWriter(scanID), nil
	default:
		return nil, fmt.Errorf("unknown output format %q: supported formats are json, bbot, xml, csv, nuclei-yaml", format)
	}
}

// MultiWriter fans out to multiple writers.
type MultiWriter struct {
	writers []Writer
}

// NewMultiWriter returns a MultiWriter that fans out to all provided writers.
func NewMultiWriter(writers ...Writer) *MultiWriter {
	return &MultiWriter{writers: writers}
}

// WritePort calls WritePort on all sub-writers, returning the first error.
func (m *MultiWriter) WritePort(r scanner.PortResult) error {
	for _, w := range m.writers {
		if err := w.WritePort(r); err != nil {
			return err
		}
	}
	return nil
}

// WriteResult calls WriteResult on all sub-writers, returning the first error.
func (m *MultiWriter) WriteResult(r *scanner.ScanResult) error {
	for _, w := range m.writers {
		if err := w.WriteResult(r); err != nil {
			return err
		}
	}
	return nil
}

// Close closes all sub-writers, returning the first error.
func (m *MultiWriter) Close() error {
	var firstErr error
	for _, w := range m.writers {
		if err := w.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
