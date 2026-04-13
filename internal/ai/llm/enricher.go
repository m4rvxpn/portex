// Package llm implements LLM-based port enrichment, nuclei template generation,
// and CVE suggestion for Portex scan results.
package llm

import (
	"context"

	"github.com/m4rvxpn/portex/internal/scanner"
)

// LLMEnricher is the interface for post-scan LLM analysis.
type LLMEnricher interface {
	// Enrich analyzes an open port and returns enrichment data.
	Enrich(ctx context.Context, port scanner.PortResult) (*scanner.LLMEnrichment, error)
	// IsEnabled returns false if LLM enrichment is disabled.
	IsEnabled() bool
}

// NoopEnricher is a disabled enricher that returns nil without error.
type NoopEnricher struct{}

func (n *NoopEnricher) Enrich(_ context.Context, _ scanner.PortResult) (*scanner.LLMEnrichment, error) {
	return nil, nil
}

func (n *NoopEnricher) IsEnabled() bool { return false }
