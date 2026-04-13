package mimicry

import "encoding/binary"

// OSWindowProfile defines TCP window sizes for a given OS fingerprint.
type OSWindowProfile struct {
	Name       string
	WindowSize uint16
	WinScale   uint8
	MSS        uint16
}

var (
	Linux4_15 = OSWindowProfile{Name: "Linux 4.15", WindowSize: 29200, WinScale: 7, MSS: 1460}
	Linux5_x  = OSWindowProfile{Name: "Linux 5.x", WindowSize: 65535, WinScale: 8, MSS: 1460}
	Windows10 = OSWindowProfile{Name: "Windows 10", WindowSize: 65535, WinScale: 8, MSS: 1460}
	Windows7  = OSWindowProfile{Name: "Windows 7", WindowSize: 8192, WinScale: 2, MSS: 1460}
	MacOS     = OSWindowProfile{Name: "macOS", WindowSize: 65535, WinScale: 6, MSS: 1460}
)

const (
	ethHLen = 14 // Ethernet header length
)

// InjectWindowProfile modifies the TCP window field in a raw frame to match
// the profile. Assumes standard Ethernet + IPv4 framing (ETH_HLEN=14, IHL
// variable). TCP window field is at bytes 14-15 of the TCP header.
// Returns a copy of the frame with the window field updated.
func InjectWindowProfile(frame []byte, profile OSWindowProfile) []byte {
	const minLen = ethHLen + 20 + 16 // Ethernet + min IPv4 + window at TCP+14
	if len(frame) < minLen {
		out := make([]byte, len(frame))
		copy(out, frame)
		return out
	}

	out := make([]byte, len(frame))
	copy(out, frame)

	// Locate TCP header start.
	ihl := int(out[ethHLen]&0x0f) * 4
	if ihl < 20 {
		ihl = 20
	}
	tcpWindowOff := ethHLen + ihl + 14

	if tcpWindowOff+2 > len(out) {
		return out
	}

	binary.BigEndian.PutUint16(out[tcpWindowOff:], profile.WindowSize)
	return out
}
