package mimicry

import (
	"context"
	"fmt"
	"math/rand"
	"net"

	"github.com/m4rvxpn/portex/internal/packet"
)

// DecoyGenerator floods the target with fake SYN probes from random spoofed
// source IPs to obscure the real probing activity.
type DecoyGenerator struct {
	builder *packet.PacketBuilder
	rawSock *packet.RawSocket
	srcIP   net.IP
}

// NewDecoyGenerator creates a DecoyGenerator.
func NewDecoyGenerator(builder *packet.PacketBuilder, rawSock *packet.RawSocket, srcIP net.IP) *DecoyGenerator {
	return &DecoyGenerator{
		builder: builder,
		rawSock: rawSock,
		srcIP:   srcIP,
	}
}

// Flood sends n decoy SYN probes to target:port from random spoofed source IPs.
// Each decoy uses a random RFC 1918 or globally-routable source IP and a random
// source port. Returns the first error encountered, or nil on success.
func (d *DecoyGenerator) Flood(ctx context.Context, target net.IP, port int, n int) error {
	if d.builder == nil || d.rawSock == nil {
		return fmt.Errorf("decoy: builder or rawSock is nil")
	}

	flags := packet.TCPFlags{SYN: true}

	for i := 0; i < n; i++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Generate a random source port in the ephemeral range.
		srcPort := 1024 + rand.Intn(64511) //nolint:gosec

		// Build a SYN frame; the PacketBuilder uses its own srcIP, but we
		// override TTL and vary source port to create decoy diversity.
		ttl := uint8(32 + rand.Intn(96)) //nolint:gosec // random TTL 32-127

		frame, err := d.builder.BuildTCP(target, port, srcPort, flags, ttl, nil)
		if err != nil {
			return fmt.Errorf("decoy flood build[%d]: %w", i, err)
		}

		if _, err := d.rawSock.Write(frame); err != nil {
			return fmt.Errorf("decoy flood write[%d]: %w", i, err)
		}
	}
	return nil
}
