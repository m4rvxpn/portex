package output

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	llm "github.com/m4rvxpn/portex/internal/ai/llm"
	"github.com/m4rvxpn/portex/internal/scanner"
)

// NucleiYAMLWriter writes nuclei template YAML files for each open port.
// Each port gets its own .yaml file in the output directory.
type NucleiYAMLWriter struct {
	outDir  string
	written int
	mu      sync.Mutex
}

// NewNucleiYAMLWriter returns a new NucleiYAMLWriter that creates template
// files inside outDir.
func NewNucleiYAMLWriter(outDir string) *NucleiYAMLWriter {
	return &NucleiYAMLWriter{outDir: outDir}
}

// WritePort generates and writes a nuclei YAML template for an open port.
// The file is named <service>-<port>.yaml inside the output directory.
func (n *NucleiYAMLWriter) WritePort(r scanner.PortResult) error {
	if r.State != scanner.StateOpen {
		return nil
	}

	content := llm.GenerateNucleiTemplate(r)

	service := "unknown"
	if r.Service != nil && r.Service.Service != "" {
		service = r.Service.Service
	}
	filename := fmt.Sprintf("%s-%d.yaml", service, r.Port)
	path := filepath.Join(n.outDir, filename)

	if err := os.MkdirAll(n.outDir, 0o750); err != nil {
		return fmt.Errorf("create nuclei output dir %q: %w", n.outDir, err)
	}

	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		return fmt.Errorf("write nuclei template %q: %w", path, err)
	}

	n.mu.Lock()
	n.written++
	n.mu.Unlock()

	return nil
}

// WriteResult writes nuclei templates for all open ports in the scan result.
func (n *NucleiYAMLWriter) WriteResult(r *scanner.ScanResult) error {
	for _, p := range r.Ports {
		if err := n.WritePort(p); err != nil {
			return err
		}
	}
	return nil
}

// Close is a no-op for NucleiYAMLWriter.
func (n *NucleiYAMLWriter) Close() error {
	return nil
}
