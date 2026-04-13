// Package mutator implements payload mutation strategies for evading IDS/IPS and
// testing firewall rule completeness during port scanning.
package mutator

import "fmt"

// Mutator is the interface for payload mutation strategies.
type Mutator interface {
	// Mutate applies a mutation to a raw packet frame.
	// Returns the mutated frame (may be a new allocation).
	Mutate(frame []byte) ([]byte, error)
	// Name returns the mutator's identifier.
	Name() string
}

// Chain applies multiple mutators in sequence.
type Chain struct {
	mutators []Mutator
}

// NewChain creates a mutator chain from the supplied mutators.
func NewChain(mutators ...Mutator) *Chain {
	return &Chain{mutators: mutators}
}

// Mutate applies each mutator in order, feeding the output of one as input to
// the next. Returns early on the first error.
func (c *Chain) Mutate(frame []byte) ([]byte, error) {
	var err error
	for _, m := range c.mutators {
		frame, err = m.Mutate(frame)
		if err != nil {
			return nil, fmt.Errorf("mutator %q: %w", m.Name(), err)
		}
	}
	return frame, nil
}

// Name returns a combined identifier for the chain.
func (c *Chain) Name() string {
	names := ""
	for i, m := range c.mutators {
		if i > 0 {
			names += "+"
		}
		names += m.Name()
	}
	if names == "" {
		return "chain(empty)"
	}
	return "chain(" + names + ")"
}
