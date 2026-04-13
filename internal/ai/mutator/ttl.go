package mutator

import (
	"encoding/binary"
	"fmt"
	"math/rand"
)

const (
	ethHLen    = 14 // standard Ethernet header length
	ipTTLOff   = ethHLen + 8  // byte offset of TTL in IPv4 header (after Ethernet)
	ipCsumOff  = ethHLen + 10 // byte offset of IP header checksum
	ipHdrStart = ethHLen      // start of IPv4 header in Ethernet frame
)

// TTLMutator randomizes the IP TTL within a configured range.
type TTLMutator struct {
	Min, Max uint8
}

// NewTTLMutator creates a TTLMutator with the given TTL range.
func NewTTLMutator(min, max uint8) *TTLMutator {
	if min > max {
		min, max = max, min
	}
	return &TTLMutator{Min: min, Max: max}
}

// Mutate sets the IP TTL to a random value in [Min, Max] and recomputes the
// IP header checksum. Assumes standard Ethernet + IPv4 framing.
func (m *TTLMutator) Mutate(frame []byte) ([]byte, error) {
	if len(frame) < ipTTLOff+1 {
		return nil, fmt.Errorf("ttl mutator: frame too short (%d bytes)", len(frame))
	}

	out := make([]byte, len(frame))
	copy(out, frame)

	// Pick a random TTL in range.
	rng := int(m.Max) - int(m.Min)
	var newTTL uint8
	if rng <= 0 {
		newTTL = m.Min
	} else {
		newTTL = m.Min + uint8(rand.Intn(rng+1)) //nolint:gosec // non-crypto randomness is fine here
	}
	out[ipTTLOff] = newTTL

	// Recalculate IP header checksum.
	ihl := int(out[ipHdrStart]&0x0f) * 4
	if ihl < 20 || ipHdrStart+ihl > len(out) {
		return nil, fmt.Errorf("ttl mutator: invalid IHL %d", ihl)
	}

	// Zero existing checksum before recalculating.
	out[ipCsumOff] = 0
	out[ipCsumOff+1] = 0

	csum := ipChecksum(out[ipHdrStart : ipHdrStart+ihl])
	binary.BigEndian.PutUint16(out[ipCsumOff:], csum)

	return out, nil
}

// Name returns the mutator identifier.
func (m *TTLMutator) Name() string { return "ttl" }

// ipChecksum computes the RFC 791 one's-complement checksum of an IP header.
func ipChecksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i:]))
	}
	if len(hdr)%2 == 1 {
		sum += uint32(hdr[len(hdr)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
