package mutator

import "fmt"

// FlagComboMutator randomly adds or removes a TCP flag from a configured set.
//
// TCP flag byte is at offset 13 within the TCP header.
// Standard flag bitmask values:
//
//	FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10, URG=0x20
type FlagComboMutator struct {
	AddFlags    uint8 // bitmask of flags to set
	RemoveFlags uint8 // bitmask of flags to clear
}

// NewFlagComboMutator creates a FlagComboMutator with the given add/remove masks.
func NewFlagComboMutator(add, remove uint8) *FlagComboMutator {
	return &FlagComboMutator{AddFlags: add, RemoveFlags: remove}
}

// Mutate applies the flag add/remove masks to the TCP flags byte.
// Assumes standard Ethernet + IPv4 + TCP framing.
func (m *FlagComboMutator) Mutate(frame []byte) ([]byte, error) {
	const minLen = ethHLen + 20 + 14 // Ethernet + min IPv4 + flags at TCP+13
	if len(frame) < minLen {
		return nil, fmt.Errorf("flagcombo mutator: frame too short (%d bytes)", len(frame))
	}

	out := make([]byte, len(frame))
	copy(out, frame)

	// Locate TCP header start.
	ihl := int(out[ethHLen]&0x0f) * 4
	if ihl < 20 {
		ihl = 20
	}
	tcpFlagsOff := ethHLen + ihl + 13

	if tcpFlagsOff >= len(out) {
		return nil, fmt.Errorf("flagcombo mutator: TCP flags offset out of range")
	}

	flags := out[tcpFlagsOff]
	flags |= m.AddFlags
	flags &^= m.RemoveFlags
	out[tcpFlagsOff] = flags

	return out, nil
}

// Name returns the mutator identifier.
func (m *FlagComboMutator) Name() string { return "flagcombo" }
