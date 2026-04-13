package rl

import "context"

// GRPCAgent connects to an external Python RL training sidecar.
// Address format: "host:port"
//
// NOTE: The real gRPC implementation (google.golang.org/grpc) and the
// proto/rl_agent.proto definition are deferred to Phase 7. This stub
// delegates to NoopAgent behavior to keep the build clean.
type GRPCAgent struct {
	addr    string
	enabled bool
}

// NewGRPCAgent creates a GRPCAgent. Returns NoopAgent if addr is empty.
func NewGRPCAgent(addr string) RLAgent {
	if addr == "" {
		return &NoopAgent{}
	}
	// TODO(phase7): Dial the gRPC sidecar at addr and wire up the
	// RLAgentServiceClient generated from proto/rl_agent.proto.
	return &GRPCAgent{
		addr:    addr,
		enabled: false, // stub: disabled until Phase 7
	}
}

// GetAction is a stub that returns an empty action.
// TODO(phase7): Replace with actual gRPC call to the Python sidecar.
func (a *GRPCAgent) GetAction(_ context.Context, _ State) (Action, error) {
	return Action{}, nil
}

// UpdateReward is a stub that discards the reward.
// TODO(phase7): Forward the reward to the Python sidecar via gRPC stream.
func (a *GRPCAgent) UpdateReward(_ context.Context, _ State, _ Action, _ float32) error {
	return nil
}

// IsEnabled returns false until Phase 7 wires the real gRPC connection.
func (a *GRPCAgent) IsEnabled() bool { return a.enabled }
