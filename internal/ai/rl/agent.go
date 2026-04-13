package rl

import "context"

// RLAgent is the interface the scanner calls per probe.
type RLAgent interface {
	// GetAction queries the model for the best next probe given current state.
	GetAction(ctx context.Context, state State) (Action, error)
	// UpdateReward provides feedback on the last action taken.
	UpdateReward(ctx context.Context, state State, action Action, reward float32) error
	// IsEnabled returns false if the agent is disabled or model failed to load.
	IsEnabled() bool
}

// NoopAgent is a disabled agent that returns zero actions.
type NoopAgent struct{}

func (n *NoopAgent) GetAction(_ context.Context, _ State) (Action, error) {
	return Action{}, nil
}

func (n *NoopAgent) UpdateReward(_ context.Context, _ State, _ Action, _ float32) error {
	return nil
}

func (n *NoopAgent) IsEnabled() bool { return false }
