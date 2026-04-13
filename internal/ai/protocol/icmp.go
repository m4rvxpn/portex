package protocol

import "context"

// ICMPProber uses ICMP echo to check host availability before TCP probing.
type ICMPProber struct{}

// NewICMPProber creates a new ICMPProber.
func NewICMPProber() *ICMPProber { return &ICMPProber{} }

// Ping sends an ICMP echo and returns true if a reply is received within the
// context deadline.
//
// Stub: returns true (host assumed up) to avoid requiring a CAP_NET_RAW raw
// socket for ICMP echo. Full implementation is deferred to Phase 7.
// TODO(phase7): Use golang.org/x/net/icmp to send/receive real ICMP echo.
func (i *ICMPProber) Ping(_ context.Context, _ string) (bool, error) {
	return true, nil
}
