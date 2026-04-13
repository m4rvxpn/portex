package rl

import "github.com/m4rvxpn/portex/internal/scanner"

const (
	RewardOpen     float32 = 1.0
	RewardFiltered float32 = -0.5
	RewardRSTStorm float32 = -1.0
	RewardStealth  float32 = 0.2  // no RST triggered
	RewardClosed   float32 = 0.0
	RewardTimeout  float32 = -0.1
)

// ComputeReward derives a scalar reward from a probe result.
func ComputeReward(result scanner.PortResult, stealthMode bool) float32 {
	switch result.State {
	case scanner.StateOpen:
		r := RewardOpen
		// Bonus for stealth: open port found without triggering RST storm
		if stealthMode && result.Reason != "rst" {
			r += RewardStealth
		}
		return r

	case scanner.StateClosed:
		// Closed but reachable — check if RST storm
		if result.Reason == "rst" && stealthMode {
			return RewardRSTStorm
		}
		return RewardClosed

	case scanner.StateFiltered:
		return RewardFiltered

	case scanner.StateOpenFiltered:
		// Partially positive — might be open
		return RewardFiltered * 0.5

	case scanner.StateUnreachable:
		return RewardTimeout

	default:
		// StateUnknown or no-response
		if result.Reason == "no-response" || result.Reason == "timeout" {
			return RewardTimeout
		}
		return RewardClosed
	}
}
