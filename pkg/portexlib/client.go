// Package portexlib is the public Go library interface for embedding Portex
// in other tools without requiring the CLI.
package portexlib

import (
	"context"
	"fmt"

	"github.com/m4rvxpn/portex/internal/config"
	"github.com/m4rvxpn/portex/internal/portex"
	"github.com/m4rvxpn/portex/internal/scanner"
)

// Client is the public Go library interface for embedding Portex in other tools.
type Client struct {
	cfg *config.Config
}

// New creates a Portex client with the given configuration.
func New(cfg *config.Config) *Client {
	if cfg == nil {
		cfg = config.Defaults()
	}
	return &Client{cfg: cfg}
}

// Scan runs a full scan and returns the aggregated result when complete.
func (c *Client) Scan(ctx context.Context) (*scanner.ScanResult, error) {
	s, err := portex.New(c.cfg)
	if err != nil {
		return nil, fmt.Errorf("portexlib: create scanner: %w", err)
	}
	defer s.Close() //nolint:errcheck

	result, err := s.Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("portexlib: scan: %w", err)
	}
	return result, nil
}

// ScanStream runs a scan and streams PortResults to the provided channel.
// The channel is closed when the scan completes.
func (c *Client) ScanStream(ctx context.Context, out chan<- scanner.PortResult) error {
	s, err := portex.New(c.cfg)
	if err != nil {
		return fmt.Errorf("portexlib: create scanner: %w", err)
	}

	if err := s.ScanStream(ctx, out); err != nil {
		s.Close() //nolint:errcheck
		return fmt.Errorf("portexlib: scan stream: %w", err)
	}

	// Close scanner resources in background once ScanStream goroutines finish.
	go func() {
		<-ctx.Done()
		s.Close() //nolint:errcheck
	}()

	return nil
}
