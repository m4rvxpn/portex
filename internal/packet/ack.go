package packet

import (
	"context"
	"net"
	"time"

	"github.com/m4rvxpn/portex/internal/scanner"
)

// ACKScanner performs TCP ACK scans (-sA).
// Unfiltered: RST response (port is not firewalled) → StateClosed, reason "rst".
// Filtered: no response or ICMP unreachable → StateFiltered.
type ACKScanner struct {
	builder *PacketBuilder
	rawSock *RawSocket
	capture *Capturer
	srcIP   net.IP
}

// NewACKScanner creates a new ACKScanner.
func NewACKScanner(builder *PacketBuilder, rawSock *RawSocket, capture *Capturer, srcIP net.IP) *ACKScanner {
	return &ACKScanner{
		builder: builder,
		rawSock: rawSock,
		capture: capture,
		srcIP:   srcIP,
	}
}

// Scan performs an ACK scan against dst:dstPort.
func (s *ACKScanner) Scan(ctx context.Context, dst net.IP, dstPort, srcPort int, ttl uint8) (scanner.PortState, string, time.Duration, error) {
	if srcPort == 0 {
		srcPort = randEphemeralPort()
	}
	if ttl == 0 {
		ttl = 64
	}

	key := CorrelationKey(dst.String(), s.srcIP.String(), dstPort, srcPort)
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
			return scanner.StateClosed, "rst", rtt, nil
		}
		return scanner.StateUnknown, "unexpected", rtt, nil
	}
}
