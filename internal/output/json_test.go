package output

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/m4rvxpn/portex/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJSONWriter_WriteResult(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONWriter(&buf)

	result := &scanner.ScanResult{
		ScanID:     "test-scan-123",
		SessionID:  "session-456",
		StartTime:  time.Now(),
		EndTime:    time.Now(),
		Targets:    []string{"127.0.0.1"},
		TotalPorts: 1,
		OpenPorts:  1,
		Ports: []scanner.PortResult{
			{
				Target:    "127.0.0.1",
				Port:      80,
				Protocol:  "tcp",
				State:     scanner.StateOpen,
				Timestamp: time.Now(),
			},
		},
	}

	err := w.WriteResult(result)
	require.NoError(t, err)

	var out map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &out)
	require.NoError(t, err, "output should be valid JSON")

	assert.Equal(t, "test-scan-123", out["scan_id"], "scan_id should be present")
	assert.Equal(t, "session-456", out["session_id"], "session_id should be present")
	_, hasTargets := out["targets"]
	assert.True(t, hasTargets, "targets field should be present")
	_, hasPorts := out["ports"]
	assert.True(t, hasPorts, "ports field should be present")
}

func TestJSONWriter_OpenPortsCount(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONWriter(&buf)

	openResult := func(port int) scanner.PortResult {
		return scanner.PortResult{
			Target:    "127.0.0.1",
			Port:      port,
			Protocol:  "tcp",
			State:     scanner.StateOpen,
			Timestamp: time.Now(),
		}
	}
	filteredResult := func(port int) scanner.PortResult {
		return scanner.PortResult{
			Target:    "127.0.0.1",
			Port:      port,
			Protocol:  "tcp",
			State:     scanner.StateFiltered,
			Timestamp: time.Now(),
		}
	}

	require.NoError(t, w.WritePort(openResult(80)))
	require.NoError(t, w.WritePort(openResult(443)))
	require.NoError(t, w.WritePort(openResult(8080)))
	require.NoError(t, w.WritePort(filteredResult(22)))
	require.NoError(t, w.WritePort(filteredResult(25)))

	err := w.WriteResult(&scanner.ScanResult{
		ScanID:  "count-test",
		Targets: []string{"127.0.0.1"},
	})
	require.NoError(t, err)

	var out map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &out)
	require.NoError(t, err)

	openPorts, ok := out["open_ports"].(float64)
	require.True(t, ok, "open_ports should be a number")
	assert.Equal(t, float64(3), openPorts, "open_ports should be 3")
}
