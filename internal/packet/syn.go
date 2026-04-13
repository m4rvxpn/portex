package packet

import (
	"context"
	"net"
	"time"

	"github.com/m4rvxpn/portex/internal/scanner"
)

// SYNScanner performs TCP SYN scans (-sS).
// Open: SYN+ACK. Closed: RST. Filtered: timeout or ICMP unreachable.
type SYNScanner struct {
	builder *PacketBuilder
	rawSock *RawSocket
	capture *Capturer
	srcIP   net.IP
}

// NewSYNScanner creates a new SYNScanner.
func NewSYNScanner(builder *PacketBuilder, rawSock *RawSocket, capture *Capturer, srcIP net.IP) *SYNScanner {
	return &SYNScanner{
		builder: builder,
		rawSock: rawSock,
		capture: capture,
		srcIP:   srcIP,
	}
}

// Scan performs a SYN scan against dst:dstPort.
func (s *SYNScanner) Scan(ctx context.Context, dst net.IP, dstPort, srcPort int, ttl uint8) (state scanner.PortState, reason string, rtt time.Duration, err error) {
	if srcPort == 0 {
		srcPort = randEphemeralPort()
	}
	if ttl == 0 {
		ttl = 64
	}

	key := CorrelationKey(dst.String(), s.srcIP.String(), dstPort, srcPort)
	ch := s.capture.Register(key)
	defer s.capture.Unregister(key)

	frame, err := s.builder.BuildTCP(dst, dstPort, srcPort, TCPFlags{SYN: true}, ttl, nil)
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
		rtt = resp.RecvAt.Sub(sent)
		if resp.Proto == "icmp" && resp.ICMP != nil && resp.ICMP.Type == 3 {
			return scanner.StateFiltered, "icmp-unreach", rtt, nil
		}
		if resp.Proto == "tcp" {
			if resp.Flags.SYN && resp.Flags.ACK {
				return scanner.StateOpen, "syn-ack", rtt, nil
			}
			if resp.Flags.RST {
				return scanner.StateClosed, "rst", rtt, nil
			}
		}
		return scanner.StateUnknown, "unexpected", rtt, nil
	}
}
