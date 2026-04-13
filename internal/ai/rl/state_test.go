package rl

import (
	"testing"

	"github.com/m4rvxpn/portex/internal/scanner"
	"github.com/stretchr/testify/assert"
)

func TestToFeatureVector_Length(t *testing.T) {
	s := State{
		Port:      80,
		PortState: scanner.StateOpen,
		Protocol:  "tcp",
	}
	vec := s.ToFeatureVector()
	assert.Len(t, vec, 12, "feature vector must have exactly 12 elements")
}

func TestToFeatureVector_Normalized(t *testing.T) {
	s := State{
		Port:         443,
		PortState:    scanner.StateFiltered,
		ResponseTime: 500.0,
		TTL:          128,
		WindowSize:   65535,
		FilterFlags:  0x03,
		Attempt:      5,
		Protocol:     "tcp",
		PrevAction:   &Action{TimingDelta: 0},
	}
	vec := s.ToFeatureVector()
	for i, v := range vec {
		assert.GreaterOrEqual(t, v, float32(0.0), "feature[%d] should be >= 0.0, got %v", i, v)
		assert.LessOrEqual(t, v, float32(1.0), "feature[%d] should be <= 1.0, got %v", i, v)
	}
}

func TestToFeatureVector_OpenPort(t *testing.T) {
	s := State{
		Port:      22,
		PortState: scanner.StateOpen,
	}
	vec := s.ToFeatureVector()
	assert.Equal(t, float32(1.0), vec[1], "open port should have feature[1] = 1.0")
}

func TestComputeReward_Open(t *testing.T) {
	result := scanner.PortResult{
		State:  scanner.StateOpen,
		Reason: "syn-ack",
	}
	r := ComputeReward(result, false)
	assert.Equal(t, RewardOpen, r, "open port should return RewardOpen")
}

func TestComputeReward_RSTStorm(t *testing.T) {
	// filtered + stealthMode triggers RST storm if closed with rst reason
	// Per reward.go: StateFiltered returns RewardFiltered (-0.5).
	// StateClosedRSTStorm returns RewardRSTStorm only when: State=closed, Reason=rst, stealthMode=true
	result := scanner.PortResult{
		State:  scanner.StateClosed,
		Reason: "rst",
	}
	r := ComputeReward(result, true)
	assert.Equal(t, RewardRSTStorm, r, "closed with RST in stealth mode should return RewardRSTStorm")
}
