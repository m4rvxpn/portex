package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/m4rvxpn/portex/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeOpenPortResult() scanner.PortResult {
	return scanner.PortResult{
		Target:    "127.0.0.1",
		Port:      80,
		Protocol:  "tcp",
		State:     scanner.StateOpen,
		Reason:    "syn-ack",
		Timestamp: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

func TestBBOTWriter_OpenPort(t *testing.T) {
	var buf bytes.Buffer
	w := NewBBOTWriter(&buf, "test-scan-id")

	r := makeOpenPortResult()
	err := w.WritePort(r)
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.NotEmpty(t, lines)

	var ev map[string]interface{}
	err = json.Unmarshal([]byte(lines[0]), &ev)
	require.NoError(t, err, "first line should be valid JSON")
	assert.Equal(t, "OPEN_TCP_PORT", ev["type"], "event type should be OPEN_TCP_PORT")
}

func TestBBOTWriter_TechnologyEvent(t *testing.T) {
	var buf bytes.Buffer
	w := NewBBOTWriter(&buf, "test-scan-id")

	r := makeOpenPortResult()
	r.Service = &scanner.ServiceMatch{
		Service: "http",
		Product: "Apache httpd",
		Version: "2.4.51",
	}

	err := w.WritePort(r)
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.GreaterOrEqual(t, len(lines), 2, "should emit at least 2 events (OPEN_TCP_PORT + TECHNOLOGY)")

	var found bool
	for _, line := range lines {
		var ev map[string]interface{}
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		if ev["type"] == "TECHNOLOGY" {
			found = true
			break
		}
	}
	assert.True(t, found, "should emit a TECHNOLOGY event when ServiceMatch is present")
}

func TestBBOTWriter_DeterministicID(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	w1 := NewBBOTWriter(&buf1, "scan-1")
	w2 := NewBBOTWriter(&buf2, "scan-1")

	r := makeOpenPortResult()

	require.NoError(t, w1.WritePort(r))
	require.NoError(t, w2.WritePort(r))

	var ev1, ev2 map[string]interface{}
	line1 := strings.SplitN(buf1.String(), "\n", 2)[0]
	line2 := strings.SplitN(buf2.String(), "\n", 2)[0]

	require.NoError(t, json.Unmarshal([]byte(line1), &ev1))
	require.NoError(t, json.Unmarshal([]byte(line2), &ev2))

	assert.Equal(t, ev1["id"], ev2["id"], "same input should produce same event ID")
}

func TestBBOTWriter_ValidJSON(t *testing.T) {
	var buf bytes.Buffer
	w := NewBBOTWriter(&buf, "test-scan-id")

	r := makeOpenPortResult()
	r.Service = &scanner.ServiceMatch{
		Service: "http",
		Product: "nginx",
		Version: "1.25",
	}
	r.LLMEnrich = &scanner.LLMEnrichment{
		Summary: "web server",
		CVEs:    []string{"CVE-2023-0001", "CVE-2023-0002", "CVE-2023-0003", "CVE-2023-0004", "CVE-2023-0005", "CVE-2023-0006"},
	}

	err := w.WritePort(r)
	require.NoError(t, err)

	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var ev map[string]interface{}
		err := json.Unmarshal([]byte(line), &ev)
		assert.NoError(t, err, "each line should be valid JSON: %q", line)
		_, hasType := ev["type"]
		assert.True(t, hasType, "each event should have a 'type' field")
	}
}
