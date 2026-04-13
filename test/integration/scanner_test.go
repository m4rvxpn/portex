//go:build integration
// +build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/m4rvxpn/portex/internal/config"
	"github.com/m4rvxpn/portex/internal/portex"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScan_Loopback_ConnectMode(t *testing.T) {
	cfg := config.Defaults()
	cfg.Targets = []string{"127.0.0.1"}
	cfg.Ports = "22"
	cfg.Mode = config.ModeConnect
	cfg.Timing = config.T4
	cfg.Goroutines = 10

	s, err := portex.New(cfg)
	if err != nil {
		t.Skipf("scanner init failed (may require CAP_NET_RAW): %v", err)
	}
	defer s.Close() //nolint:errcheck

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := s.Scan(ctx)
	require.NoError(t, err)
	require.NotNil(t, result)

	// If SSH is running on 127.0.0.1:22, expect state=open
	for _, pr := range result.Ports {
		if pr.Port == 22 {
			// Accept open or closed; just verify we got a result
			assert.NotEmpty(t, string(pr.State), "port 22 should have a state")
			return
		}
	}
	// No result for port 22 is also acceptable (host may have no SSH)
}
