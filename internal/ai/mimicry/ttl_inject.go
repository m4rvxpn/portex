package mimicry

import "encoding/binary"

// InjectTTL sets the TTL field in a raw IP frame (Ethernet header assumed at
// offset 0) and recalculates the IP header checksum.
// Returns a modified copy of the frame; the original is not mutated.
func InjectTTL(frame []byte, ttl uint8) []byte {
	const (
		ipTTLOff  = ethHLen + 8  // byte offset of TTL in IPv4 header
		ipCsumOff = ethHLen + 10 // byte offset of IP header checksum
	)

	if len(frame) < ipTTLOff+1 {
		out := make([]byte, len(frame))
		copy(out, frame)
		return out
	}

	out := make([]byte, len(frame))
	copy(out, frame)

	out[ipTTLOff] = ttl

	// Recalculate IP checksum.
	ihl := int(out[ethHLen]&0x0f) * 4
	if ihl < 20 || ethHLen+ihl > len(out) {
		return out
	}

	out[ipCsumOff] = 0
	out[ipCsumOff+1] = 0
	csum := ipChecksum(out[ethHLen : ethHLen+ihl])
	binary.BigEndian.PutUint16(out[ipCsumOff:], csum)

	return out
}

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
