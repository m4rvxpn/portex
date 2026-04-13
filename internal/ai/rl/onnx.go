package rl

import "context"

// ONNXAgent runs a pre-trained ONNX policy model.
// If the ONNX runtime library is not available, it falls back to a
// heuristic action policy so scans can still run.
//
// NOTE: The real ONNX runtime integration (github.com/yalue/onnxruntime_go)
// will be wired in Phase 7. For now this uses a pure-Go heuristic policy
// to avoid requiring the ONNX Runtime shared library at build time.
type ONNXAgent struct {
	enabled   bool
	modelPath string
}

// NewONNXAgent loads an ONNX model from the given file path.
// Returns a NoopAgent if modelPath is empty.
// Returns an ONNXAgent with heuristic fallback if the model cannot be loaded.
func NewONNXAgent(modelPath string) RLAgent {
	if modelPath == "" {
		return &NoopAgent{}
	}
	// TODO(phase7): Attempt to load the ONNX model via onnxruntime_go.
	// For now, return a heuristic agent that doesn't require the .onnx file to exist.
	return &ONNXAgent{
		enabled:   true,
		modelPath: modelPath,
	}
}

// GetAction applies the heuristic fallback policy.
//
// Heuristic rules (in priority order):
//  1. If filtered flag set (0x01): switch scan mode to evade the filter.
//  2. If RST storm flag set (0x02): slow down timing to reduce noise.
//  3. If attempt > 3: try a different protocol.
//  4. Otherwise: return empty Action (keep current settings).
func (a *ONNXAgent) GetAction(_ context.Context, state State) (Action, error) {
	if !a.enabled {
		return Action{}, nil
	}

	action := Action{}

	if state.FilterFlags&0x01 != 0 {
		// Filtered — try a different scan mode to bypass the filter
		switch state.Protocol {
		case "tcp":
			action.ScanMode = "ack" // ACK scan to probe filter rules
		default:
			action.ScanMode = "syn"
		}
		action.TimingDelta = -1 // slow down while switching
		return action, nil
	}

	if state.FilterFlags&0x02 != 0 {
		// RST storm detected — back off timing
		action.TimingDelta = -1
		return action, nil
	}

	if state.Attempt > 3 {
		// Multiple failed attempts — try a different protocol
		switch state.Protocol {
		case "tcp":
			action.SwitchProto = "udp"
		case "udp":
			action.SwitchProto = "sctp"
		default:
			action.SwitchProto = "tcp"
		}
		return action, nil
	}

	// Default: no change
	return action, nil
}

func (a *ONNXAgent) UpdateReward(_ context.Context, _ State, _ Action, _ float32) error {
	// TODO(phase7): Forward reward to the ONNX training buffer / experience replay.
	return nil
}

func (a *ONNXAgent) IsEnabled() bool { return a.enabled }
