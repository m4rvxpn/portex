package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePortSpec_Top100(t *testing.T) {
	cfg := Defaults()
	ports, err := cfg.ParsePortSpec("top100")
	require.NoError(t, err)
	assert.Len(t, ports, 100, "top100 should return exactly 100 ports")
	for _, p := range ports {
		assert.GreaterOrEqual(t, p, 1, "port should be >= 1")
		assert.LessOrEqual(t, p, 65535, "port should be <= 65535")
	}
}

func TestParsePortSpec_Range(t *testing.T) {
	cfg := Defaults()
	ports, err := cfg.ParsePortSpec("80-85")
	require.NoError(t, err)
	assert.Equal(t, []int{80, 81, 82, 83, 84, 85}, ports)
}

func TestParsePortSpec_Comma(t *testing.T) {
	cfg := Defaults()
	ports, err := cfg.ParsePortSpec("22,80,443")
	require.NoError(t, err)
	assert.Equal(t, []int{22, 80, 443}, ports)
}

func TestParsePortSpec_Mixed(t *testing.T) {
	cfg := Defaults()
	ports, err := cfg.ParsePortSpec("22,80-82,443")
	require.NoError(t, err)
	assert.Equal(t, []int{22, 80, 81, 82, 443}, ports)
}

func TestParsePortSpec_All(t *testing.T) {
	cfg := Defaults()
	ports, err := cfg.ParsePortSpec("all")
	require.NoError(t, err)
	assert.Len(t, ports, 65535, "all should return 65535 ports")
}

func TestValidate_IdleScanRequiresZombie(t *testing.T) {
	cfg := Defaults()
	cfg.Mode = ModeIdle
	cfg.ZombieHost = ""
	err := cfg.Validate()
	assert.Error(t, err, "idle scan without zombie_host should fail validation")
}

func TestDefaults(t *testing.T) {
	cfg := Defaults()
	require.NotNil(t, cfg)
	assert.Equal(t, 5000, cfg.Goroutines)
	assert.Equal(t, ModeSYN, cfg.Mode)
	assert.Equal(t, T3, cfg.Timing)
}
