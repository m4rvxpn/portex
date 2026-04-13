package mutator

import (
	"encoding/binary"
	"fmt"
	"math/rand"
)

// UrgentMutator sets the TCP urgent pointer to a random non-zero value and
// ensures the URG flag is set in the TCP flags byte.
//
// TCP header offsets (relative to TCP header start):
//   - Flags byte: offset 13
//   - Urgent pointer: offsets 18-19
type UrgentMutator struct{}

// NewUrgentMutator creates a new UrgentMutator.
func NewUrgentMutator() *UrgentMutator { return &UrgentMutator{} }

// Mutate injects a random non-zero urgent pointer into the TCP header and sets
// the URG flag. Assumes standard Ethernet + IPv4 + TCP framing.
func (m *UrgentMutator) Mutate(frame []byte) ([]byte, error) {
	const minLen = ethHLen + 20 + 20 // Ethernet + min IPv4 + min TCP
	if len(frame) < minLen {
		return nil, fmt.Errorf("urgent mutator: frame too short (%d bytes)", len(frame))
	}

	out := make([]byte, len(frame))
	copy(out, frame)

	// Locate TCP header start: Ethernet(14) + IPv4(IHL*4)
	ihl := int(out[ethHLen]&0x0f) * 4
	if ihl < 20 {
		ihl = 20
	}
	tcpStart := ethHLen + ihl

	if tcpStart+20 > len(out) {
		return nil, fmt.Errorf("urgent mutator: not enough room for TCP header")
	}

	// Set URG flag (bit 5 of flags byte at TCP offset 13).
	const urgFlag = 0x20
	out[tcpStart+13] |= urgFlag

	// Set urgent pointer to a random non-zero uint16.
	urgPtr := uint16(rand.Intn(0xffff) + 1) //nolint:gosec
	binary.BigEndian.PutUint16(out[tcpStart+18:], urgPtr)

	return out, nil
}

// Name returns the mutator identifier.
func (m *UrgentMutator) Name() string { return "urgent" }
