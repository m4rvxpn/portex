package rl

import "github.com/m4rvxpn/portex/internal/scanner"

// State captures all scanner-observable context for the RL agent.
type State struct {
	Port         int
	PortState    scanner.PortState
	ResponseTime float32  // milliseconds
	TTL          uint8
	WindowSize   uint16
	FilterFlags  uint8    // bitmask: 0x01=filtered, 0x02=rst_storm, 0x04=timeout
	Attempt      int
	Protocol     string
	PrevAction   *Action  // nil on first probe
}

// Action is the agent's output — what to change about the next probe.
type Action struct {
	ScanMode    string // switch scan type (empty = keep current)
	TimingDelta int    // -1=slower, 0=keep, +1=faster
	SrcPort     int    // override source port (0=random)
	TCPFlagMod  uint8  // bitmask of flags to toggle
	TTLValue    uint8  // override TTL (0=keep)
	FragOffset  uint16 // fragmentation (0=none)
	UseDecoy    bool   // trigger decoy flood
	SwitchProto string // "tcp"/"udp"/"sctp" (empty=keep)
}

// StateFeatureLen is the number of float32 features in a State.
const StateFeatureLen = 12

// ToFeatureVector converts a State to a fixed-length float32 slice for model input.
// Feature layout:
//  1. port / 65535.0
//  2. portState encoded: open=1.0, closed=0.0, filtered=0.5, open|filtered=0.25
//  3. responseTime / 10000.0
//  4. ttl / 255.0
//  5. windowSize / 65535.0
//  6. filterFlags bit 0 (filtered)
//  7. filterFlags bit 1 (rst_storm)
//  8. filterFlags bit 2 (timeout)
//  9. attempt / 10.0
// 10. protocol: tcp=0.33, udp=0.66, sctp=1.0, other=0.0
// 11. prevAction != nil: 1.0 else 0.0
// 12. prevAction.TimingDelta / 2.0 + 0.5
func (s State) ToFeatureVector() []float32 {
	vec := make([]float32, StateFeatureLen)

	// Feature 1: port normalized
	vec[0] = float32(s.Port) / 65535.0

	// Feature 2: port state encoded
	switch s.PortState {
	case scanner.StateOpen:
		vec[1] = 1.0
	case scanner.StateClosed:
		vec[1] = 0.0
	case scanner.StateFiltered:
		vec[1] = 0.5
	case scanner.StateOpenFiltered:
		vec[1] = 0.25
	default:
		vec[1] = 0.0
	}

	// Feature 3: response time normalized (0-10s range)
	vec[2] = s.ResponseTime / 10000.0

	// Feature 4: TTL normalized
	vec[3] = float32(s.TTL) / 255.0

	// Feature 5: window size normalized
	vec[4] = float32(s.WindowSize) / 65535.0

	// Features 6-8: filter flag bits
	vec[5] = float32((s.FilterFlags >> 0) & 0x01)
	vec[6] = float32((s.FilterFlags >> 1) & 0x01)
	vec[7] = float32((s.FilterFlags >> 2) & 0x01)

	// Feature 9: attempt normalized (clamped to [0,10] to keep vector in [0,1])
	vec[8] = float32(min(s.Attempt, 10)) / 10.0

	// Feature 10: protocol encoded
	switch s.Protocol {
	case "tcp":
		vec[9] = 0.33
	case "udp":
		vec[9] = 0.66
	case "sctp":
		vec[9] = 1.0
	default:
		vec[9] = 0.0
	}

	// Feature 11: has previous action
	if s.PrevAction != nil {
		vec[10] = 1.0
	} else {
		vec[10] = 0.0
	}

	// Feature 12: previous action timing delta normalized
	if s.PrevAction != nil {
		vec[11] = float32(s.PrevAction.TimingDelta)/2.0 + 0.5
	} else {
		vec[11] = 0.5 // neutral (0 delta) when no previous action
	}

	return vec
}
