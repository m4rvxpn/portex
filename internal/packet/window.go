package packet

import (
	"context"
	"net"
	"time"

	"github.com/m4rvxpn/portex/internal/scanner"
)

// WindowScanner performs Window scans (-sW): same as ACK but examines the
// TCP window field in RST responses.
// RST with window > 0 → Open. RST with window == 0 → Closed.
// No response / ICMP → Filtered.
type WindowScanner struct {
	builder *PacketBuilder
	rawSock *RawSocket
	capture *Capturer
	srcIP   net.IP
}

// NewWindowScanner creates a new WindowScanner.
func NewWindowScanner(builder *PacketBuilder, rawSock *RawSocket, capture *Capturer, srcIP net.IP) *WindowScanner {
	return &WindowScanner{
		builder: builder,
		rawSock: rawSock,
		capture: capture,
		srcIP:   srcIP,
	}
}

// Scan performs a Window scan against dst:dstPort.
func (s *WindowScanner) Scan(ctx context.Context, dst net.IP, dstPort, srcPort int, ttl uint8) (scanner.PortState, string, time.Duration, error) {
	if srcPort == 0 {
		srcPort = randEphemeralPort()
	}
	if ttl == 0 {
		ttl = 64
	}

	key := CorrelationKey(s.srcIP.String(), dst.String(), srcPort, dstPort)
	ch := s.capture.Register(key)
	defer s.capture.Unregister(key)

	frame, err := s.builder.BuildTCP(dst, dstPort, srcPort, TCPFlags{ACK: true}, ttl, nil)
	if err != nil {
		return scanner.StateUnknown, "build-error", 0, err
	}

	sent := time.Now()
	if _, err := s.rawSock.Write(frame); err != nil {
		return scanner.StateUnknown, "send-error", 0, err
	}

	select {
	case <-ctx.Done():
		return scanner.StateFiltered, "no-response", 0, nil
	case resp := <-ch:
		rtt := resp.RecvAt.Sub(sent)
		if resp.Proto == "icmp" && resp.ICMP != nil && resp.ICMP.Type == 3 {
			return scanner.StateFiltered, "icmp-unreach", rtt, nil
		}
		if resp.Proto == "tcp" && resp.Flags.RST {
			if resp.Window > 0 {
				return scanner.StateOpen, "rst-window", rtt, nil
			}
			return scanner.StateClosed, "rst", rtt, nil
		}
		return scanner.StateUnknown, "unexpected", rtt, nil
	}
}
