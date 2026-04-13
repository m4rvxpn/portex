//go:build integration
// +build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/m4rvxpn/portex/internal/config"
	"github.com/m4rvxpn/portex/internal/output"
	"github.com/m4rvxpn/portex/internal/portex"
	"github.com/m4rvxpn/portex/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBBOTOutput_ValidNDJSON(t *testing.T) {
	cfg := config.Defaults()
	cfg.Targets = []string{"127.0.0.1"}
	cfg.Ports = "22,80,443"
	cfg.Mode = config.ModeConnect
	cfg.Timing = config.T4
	cfg.Goroutines = 10

	s, err := portex.New(cfg)
	if err != nil {
		t.Skipf("scanner init failed (may require CAP_NET_RAW): %v", err)
	}
	defer s.Close() //nolint:errcheck

	var buf bytes.Buffer
	w := output.NewBBOTWriter(&buf, "integration-test-scan")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resultCh := make(chan scanner.PortResult, 100)
	err = s.ScanStream(ctx, resultCh)
	require.NoError(t, err)

	for pr := range resultCh {
		if pr.State == scanner.StateOpen {
			require.NoError(t, w.WritePort(pr))
		}
	}

	output := buf.String()
	if output == "" {
		t.Skip("no open ports found on loopback; skipping NDJSON validation")
	}

	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if line == "" {
			continue
		}
		var ev map[string]interface{}
		err := json.Unmarshal([]byte(line), &ev)
		assert.NoError(t, err, "each line should be valid JSON")
		if err == nil {
			_, hasType := ev["type"]
			assert.True(t, hasType, "each BBOT event should have a 'type' field")
		}
	}
}
