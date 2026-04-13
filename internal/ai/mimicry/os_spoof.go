package mimicry

import (
	"encoding/binary"
	"math/rand"
)

// OSProfile combines window + TTL + other TCP stack properties for a realistic
// OS fingerprint.
type OSProfile struct {
	Window OSWindowProfile
	TTL    uint8
	DFBit  bool
}

var (
	ProfileLinux5  = OSProfile{Window: Linux5_x, TTL: 64, DFBit: true}
	ProfileWindows = OSProfile{Window: Windows10, TTL: 128, DFBit: true}
	ProfileMacOS   = OSProfile{Window: MacOS, TTL: 64, DFBit: true}
	ProfileRandom  = OSProfile{} // randomized per probe — filled by ApplyOSProfile
)

// ApplyOSProfile injects the OS profile's window and TTL into a raw frame.
// If the profile is ProfileRandom (zero value), random values are generated.
// Returns a modified copy of the frame.
func ApplyOSProfile(frame []byte, profile OSProfile) []byte {
	const (
		ipFlagsOff = ethHLen + 6  // IPv4 flags+fragment-offset field (2 bytes)
		ipCsumOff  = ethHLen + 10 // IPv4 checksum offset
	)

	if len(frame) < ethHLen+20 {
		out := make([]byte, len(frame))
		copy(out, frame)
		return out
	}

	// Resolve random profile.
	p := profile
	if p.TTL == 0 && p.Window.WindowSize == 0 {
		// ProfileRandom: pick a random OS fingerprint from the known set.
		profiles := []OSProfile{ProfileLinux5, ProfileWindows, ProfileMacOS}
		p = profiles[rand.Intn(len(profiles))] //nolint:gosec
	}

	// Apply window first.
	out := InjectWindowProfile(frame, p.Window)

	// Apply TTL.
	out = InjectTTL(out, p.TTL)

	// Apply DF bit in IPv4 flags (bit 1 of the flags nibble at byte offset 6).
	if len(out) >= ethHLen+8 {
		flagsAndOffset := binary.BigEndian.Uint16(out[ipFlagsOff:])
		const dfBitMask = 0x4000 // bit 14 of the 16-bit flags+offset field
		if p.DFBit {
			flagsAndOffset |= dfBitMask
		} else {
			flagsAndOffset &^= dfBitMask
		}
		binary.BigEndian.PutUint16(out[ipFlagsOff:], flagsAndOffset)

		// Recalculate IP checksum after DF bit change.
		ihl := int(out[ethHLen]&0x0f) * 4
		if ihl >= 20 && ethHLen+ihl <= len(out) {
			out[ipCsumOff] = 0
			out[ipCsumOff+1] = 0
			csum := ipChecksum(out[ethHLen : ethHLen+ihl])
			binary.BigEndian.PutUint16(out[ipCsumOff:], csum)
		}
	}

	return out
}
