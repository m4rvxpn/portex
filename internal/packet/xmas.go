package packet

import (
	"context"
	"net"
	"time"

	"github.com/m4rvxpn/portex/internal/scanner"
)

// XMASScanner performs XMAS scans (-sX): FIN+PSH+URG flags.
// Open|Filtered: no response. Closed: RST.
type XMASScanner struct {
	builder *PacketBuilder
	rawSock *RawSocket
	capture *Capturer
	srcIP   net.IP
}

// NewXMASScanner creates a new XMASScanner.
func NewXMASScanner(builder *PacketBuilder, rawSock *RawSocket, capture *Capturer, srcIP net.IP) *XMASScanner {
	return &XMASScanner{
		builder: builder,
		rawSock: rawSock,
		capture: capture,
		srcIP:   srcIP,
	}
}

// Scan performs an XMAS scan against dst:dstPort.
func (s *XMASScanner) Scan(ctx context.Context, dst net.IP, dstPort, srcPort int, ttl uint8) (scanner.PortState, string, time.Duration, error) {
	if srcPort == 0 {
		srcPort = randEphemeralPort()
	}
	if ttl == 0 {
		ttl = 64
	}

	key := CorrelationKey(s.srcIP.String(), dst.String(), srcPort, dstPort)
	ch := s.capture.Register(key)
	defer s.capture.Unregister(key)

	frame, err := s.builder.BuildTCP(dst, dstPort, srcPort, TCPFlags{FIN: true, PSH: true, URG: true}, ttl, nil)
	if err != nil {
		return scanner.StateUnknown, "build-error", 0, err
	}

	sent := time.Now()
	if _, err := s.rawSock.Write(frame); err != nil {
		return scanner.StateUnknown, "send-error", 0, err
	}

	select {
	case <-ctx.Done():
		return scanner.StateOpenFiltered, "no-response", 0, nil
	case resp := <-ch:
		rtt := resp.RecvAt.Sub(sent)
		if resp.Proto == "icmp" && resp.ICMP != nil && resp.ICMP.Type == 3 {
			return scanner.StateFiltered, "icmp-unreach", rtt, nil
		}
		if resp.Proto == "tcp" && resp.Flags.RST {
			return scanner.StateClosed, "rst", rtt, nil
		}
		return scanner.StateOpenFiltered, "unexpected", rtt, nil
	}
}
