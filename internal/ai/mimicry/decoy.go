package mimicry

import (
	"context"
	"fmt"
	"math/rand"
	"net"

	"github.com/m4rvxpn/portex/internal/packet"
)

// randomGlobalUnicastIP returns a random-looking public IPv4 address.
// Avoids RFC1918, loopback, multicast, and reserved ranges.
func randomGlobalUnicastIP() net.IP {
	for {
		a := uint8(rand.Intn(223) + 1) //nolint:gosec // 1-223
		b := uint8(rand.Intn(256))      //nolint:gosec
		c := uint8(rand.Intn(256))      //nolint:gosec
		d := uint8(rand.Intn(254) + 1)  //nolint:gosec
		// skip private ranges: 10.x, 172.16-31.x, 192.168.x
		if a == 10 {
			continue
		}
		if a == 172 && b >= 16 && b <= 31 {
			continue
		}
		if a == 192 && b == 168 {
			continue
		}
		if a == 127 {
			continue
		}
		return net.IP{a, b, c, d}
	}
}

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
// Each decoy uses a random globally-routable source IP and a random source port.
// Returns ctx.Err() if cancelled, nil on success.
func (d *DecoyGenerator) Flood(ctx context.Context, target net.IP, port int, n int) error {
	if d.builder == nil || d.rawSock == nil {
		return fmt.Errorf("decoy: builder or rawSock is nil")
	}

	flags := packet.TCPFlags{SYN: true}

	for i := 0; i < n; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		spoofSrc := randomGlobalUnicastIP()
		srcPort := 1024 + rand.Intn(64511)   //nolint:gosec
		ttl := uint8(rand.Intn(128) + 32)     //nolint:gosec // 32-159

		frame, err := d.builder.BuildTCPSpoofed(spoofSrc, target, port, srcPort, flags, ttl, nil)
		if err != nil {
			continue
		}
		_, _ = d.rawSock.Write(frame)
	}
	return nil
}
