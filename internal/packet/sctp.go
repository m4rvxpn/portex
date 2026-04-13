package packet

import (
	"context"
	"net"
	"time"

	"github.com/m4rvxpn/portex/internal/scanner"
)

// SCTPScanner performs SCTP INIT scans (-sY).
// Open: INIT-ACK. Closed: ABORT. Filtered: timeout/ICMP unreachable.
type SCTPScanner struct {
	builder *PacketBuilder
	rawSock *RawSocket
	capture *Capturer
	srcIP   net.IP
}

// NewSCTPScanner creates a new SCTPScanner.
func NewSCTPScanner(builder *PacketBuilder, rawSock *RawSocket, capture *Capturer, srcIP net.IP) *SCTPScanner {
	return &SCTPScanner{
		builder: builder,
		rawSock: rawSock,
		capture: capture,
		srcIP:   srcIP,
	}
}

// Scan performs an SCTP INIT scan against dst:dstPort.
func (s *SCTPScanner) Scan(ctx context.Context, dst net.IP, dstPort, srcPort int, initTag uint32) (scanner.PortState, string, time.Duration, error) {
	if srcPort == 0 {
		srcPort = randEphemeralPort()
	}
	if initTag == 0 {
		initTag = randUint32()
	}

	key := CorrelationKey(s.srcIP.String(), dst.String(), srcPort, dstPort)
	ch := s.capture.Register(key)
	defer s.capture.Unregister(key)

	frame, err := s.builder.BuildSCTP(dst, dstPort, srcPort, initTag)
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
		if resp.Proto == "sctp" {
			// Check for INIT-ACK vs ABORT in the raw payload.
			// SCTP chunk type 2 = INIT ACK, chunk type 6 = ABORT
			// We inspect the raw payload since gopacket may not decode INIT-ACK automatically.
			if len(resp.Payload) > 0 {
				chunkType := resp.Payload[0]
				switch chunkType {
				case 2: // INIT-ACK
					return scanner.StateOpen, "init-ack", rtt, nil
				case 6: // ABORT
					return scanner.StateClosed, "abort", rtt, nil
				}
			}
			return scanner.StateOpen, "sctp-response", rtt, nil
		}
		return scanner.StateUnknown, "unexpected", rtt, nil
	}
}
