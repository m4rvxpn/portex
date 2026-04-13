package mutator

import (
	"encoding/binary"
)

// FragMutator splits IP packets into two fragments.
// The split point is after the IP header + first 8 bytes of payload.
//
// Output format: [4-byte len][frame1][4-byte len][frame2]
// where each length prefix is big-endian uint32.
type FragMutator struct {
	Offset uint16 // fragment offset for first fragment
}

// NewFragMutator creates a FragMutator with default offset 0.
func NewFragMutator() *FragMutator {
	return &FragMutator{Offset: 0}
}

// Mutate attempts to fragment the IP packet in the frame.
// Assumes standard Ethernet framing (14-byte header) followed by an IPv4 header.
//
// TODO(phase7): Implement full RFC 791 IP fragmentation: set MF bit in the
// first fragment, adjust fragment offset field, recalculate checksums, and
// produce two independently valid IP packets. For now returns the original
// frame in the two-fragment length-prefixed format (both parts identical)
// so the interface contract is satisfied without breaking the build.
func (m *FragMutator) Mutate(frame []byte) ([]byte, error) {
	const ethHLen = 14

	if len(frame) < ethHLen+20 {
		// Frame too short to be a valid IPv4+Ethernet packet; return as-is.
		out := make([]byte, 4+len(frame))
		binary.BigEndian.PutUint32(out[0:4], uint32(len(frame)))
		copy(out[4:], frame)
		return out, nil
	}

	// Determine IP header length from IHL field.
	ihl := int(frame[ethHLen]&0x0f) * 4
	if ihl < 20 {
		ihl = 20
	}

	splitAt := ethHLen + ihl + 8 // after IP header + 8 bytes of transport
	if splitAt >= len(frame) {
		splitAt = len(frame)
	}

	frag1 := frame[:splitAt]
	frag2 := frame[splitAt:]
	if len(frag2) == 0 {
		frag2 = frame // degenerate: produce two copies
	}

	// TODO(phase7): Set the MF bit in frag1's IP flags field (byte ethHLen+6,
	// top 3 bits) and set frag2's fragment offset appropriately.

	out := make([]byte, 4+len(frag1)+4+len(frag2))
	binary.BigEndian.PutUint32(out[0:4], uint32(len(frag1)))
	copy(out[4:], frag1)
	binary.BigEndian.PutUint32(out[4+len(frag1):], uint32(len(frag2)))
	copy(out[4+len(frag1)+4:], frag2)

	return out, nil
}

// Name returns the mutator identifier.
func (m *FragMutator) Name() string { return "frag" }
