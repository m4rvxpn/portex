package mutator

import "fmt"

// ValidateMutated checks that a mutated frame is still a valid IP packet
// (correct version, minimum length, coherent IHL).
// Returns nil if valid, error otherwise.
func ValidateMutated(frame []byte) error {
	const minFrame = ethHLen + 20 // Ethernet + minimum IPv4 header

	if len(frame) < minFrame {
		return fmt.Errorf("validate: frame too short: %d bytes (min %d)", len(frame), minFrame)
	}

	ipByte0 := frame[ethHLen]

	version := (ipByte0 >> 4) & 0x0f
	if version != 4 {
		return fmt.Errorf("validate: expected IPv4 (version 4), got version %d", version)
	}

	ihl := int(ipByte0&0x0f) * 4
	if ihl < 20 {
		return fmt.Errorf("validate: IHL %d is less than minimum 20 bytes", ihl)
	}

	if ethHLen+ihl > len(frame) {
		return fmt.Errorf("validate: IHL %d exceeds frame length %d", ihl, len(frame)-ethHLen)
	}

	return nil
}
