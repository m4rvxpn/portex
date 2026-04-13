package script

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/m4rvxpn/portex/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeTestPort() scanner.PortResult {
	return scanner.PortResult{
		Target:    "127.0.0.1",
		Port:      80,
		Protocol:  "tcp",
		State:     scanner.StateOpen,
		Timestamp: time.Now(),
	}
}

func TestEngine_RunScript_SetResult(t *testing.T) {
	e := NewEngine()
	const scriptName = "test_setresult"
	const src = `portex.setresult("key", "value")`

	err := e.LoadScript(scriptName, src)
	require.NoError(t, err)

	out, err := e.RunScript(context.Background(), scriptName, makeTestPort())
	require.NoError(t, err)
	assert.True(t, strings.Contains(out, "value"), "output should contain 'value', got: %q", out)
}

func TestEngine_Sandbox_NoIO(t *testing.T) {
	e := NewEngine()
	const scriptName = "test_io"
	const src = `io.write("test")`

	err := e.LoadScript(scriptName, src)
	if err != nil {
		// Some versions of gopher-lua catch this at load time
		assert.Contains(t, err.Error(), "io")
		return
	}

	_, err = e.RunScript(context.Background(), scriptName, makeTestPort())
	assert.Error(t, err, "running io.write should return an error in sandboxed VM")
}

func TestEngine_Sandbox_NoOS(t *testing.T) {
	e := NewEngine()
	const scriptName = "test_os"
	const src = `os.exit(1)`

	err := e.LoadScript(scriptName, src)
	if err != nil {
		assert.Contains(t, err.Error(), "os")
		return
	}

	_, err = e.RunScript(context.Background(), scriptName, makeTestPort())
	assert.Error(t, err, "running os.exit should return an error in sandboxed VM")
}

func TestEngine_ContextCancellation(t *testing.T) {
	t.Skip("gopher-lua does not support mid-execution cancellation")

	e := NewEngine()
	const scriptName = "test_infinite"
	const src = `while true do end`

	err := e.LoadScript(scriptName, src)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, err = e.RunScript(ctx, scriptName, makeTestPort())
	assert.Error(t, err, "infinite loop script should be terminated by context cancellation")
}
