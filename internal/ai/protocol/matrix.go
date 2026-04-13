// Package protocol implements the protocol obfuscation matrix and specialized
// protocol probers for the Portex AI scanning pipeline.
package protocol

import "github.com/m4rvxpn/portex/internal/ai/rl"

// ProtocolMatrix selects the optimal probe variant based on the RL action.
type ProtocolMatrix struct{}

// NewProtocolMatrix creates a new ProtocolMatrix.
func NewProtocolMatrix() *ProtocolMatrix { return &ProtocolMatrix{} }

// Select returns the scan mode and protocol to use given the RL action and
// current mode.
//
// Priority order:
//  1. action.ScanMode is set → use it directly, infer proto from mode.
//  2. action.SwitchProto is set → map proto to a suitable scan mode.
//  3. Otherwise → return currentMode unchanged.
func (m *ProtocolMatrix) Select(currentMode string, action rl.Action) (scanMode string, proto string) {
	if action.ScanMode != "" {
		return action.ScanMode, protoFromMode(action.ScanMode)
	}

	if action.SwitchProto != "" {
		return modeFromProto(action.SwitchProto), action.SwitchProto
	}

	return currentMode, protoFromMode(currentMode)
}

// protoFromMode infers the IP protocol string for a given scan mode name.
func protoFromMode(mode string) string {
	switch mode {
	case "udp":
		return "udp"
	case "sctp_init", "sctp_cookie":
		return "sctp"
	default:
		return "tcp"
	}
}

// modeFromProto maps an IP protocol name to its default scan mode.
func modeFromProto(proto string) string {
	switch proto {
	case "udp":
		return "udp"
	case "sctp":
		return "sctp_init"
	default:
		return "syn"
	}
}
