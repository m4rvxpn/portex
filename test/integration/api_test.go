//go:build integration
// +build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/m4rvxpn/portex/internal/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// findFreePort returns an available TCP port on localhost.
func findFreePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func TestAPI_StartAndGetScan(t *testing.T) {
	port, err := findFreePort()
	require.NoError(t, err)

	bind := fmt.Sprintf("127.0.0.1:%d", port)
	srv := api.NewServer(bind, "") // no API key for test

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = srv.Start(ctx)
	}()

	// Wait for server to be ready
	baseURL := fmt.Sprintf("http://%s", bind)
	require.Eventually(t, func() bool {
		resp, err := http.Get(baseURL + "/v1/health")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 5*time.Second, 100*time.Millisecond, "server should start within 5 seconds")

	// POST /v1/scan
	reqBody := `{
		"targets": ["127.0.0.1"],
		"ports": "80",
		"mode": "connect",
		"timing": 4
	}`
	resp, err := http.Post(baseURL+"/v1/scan", "application/json", bytes.NewBufferString(reqBody))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusAccepted, resp.StatusCode, "POST /v1/scan should return 202")

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var scanResp map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &scanResp), "response should be valid JSON")

	scanID, ok := scanResp["scan_id"].(string)
	require.True(t, ok, "response should contain scan_id")
	require.NotEmpty(t, scanID)

	// GET /v1/scan/{id}
	statusResp, err := http.Get(fmt.Sprintf("%s/v1/scan/%s", baseURL, scanID))
	require.NoError(t, err)
	defer statusResp.Body.Close()

	assert.Equal(t, http.StatusOK, statusResp.StatusCode, "GET /v1/scan/{id} should return 200")

	statusBody, err := io.ReadAll(statusResp.Body)
	require.NoError(t, err)

	var status map[string]interface{}
	require.NoError(t, json.Unmarshal(statusBody, &status), "status response should be valid JSON")

	state, ok := status["state"].(string)
	require.True(t, ok, "status should contain 'state' field")
	assert.Contains(t, []string{"running", "completed", "failed"}, state,
		"state should be one of: running, completed, failed")
}
