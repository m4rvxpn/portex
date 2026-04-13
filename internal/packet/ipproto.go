package packet

import (
	"context"
	"net"
	"time"

	"github.com/m4rvxpn/portex/internal/scanner"
)

// IPProtoScanner performs IP Protocol scans (-sO).
// Tests which IP protocols are supported by sending raw IP datagrams with
// various protocol numbers.
// Open: any response with matching protocol.
// Closed: ICMP proto unreachable (type 3 code 2).
// Filtered: other ICMP unreachable or timeout.
type IPProtoScanner struct {
	builder *PacketBuilder
	rawSock *RawSocket
	capture *Capturer
	srcIP   net.IP
}

// NewIPProtoScanner creates a new IPProtoScanner.
func NewIPProtoScanner(builder *PacketBuilder, rawSock *RawSocket, capture *Capturer, srcIP net.IP) *IPProtoScanner {
	return &IPProtoScanner{
		builder: builder,
		rawSock: rawSock,
		capture: capture,
		srcIP:   srcIP,
	}
}

// ScanProto tests whether the given IP protocol number is supported by dst.
func (s *IPProtoScanner) ScanProto(ctx context.Context, dst net.IP, proto uint8) (scanner.PortState, string, time.Duration, error) {
	// Use a pseudo-key based on protocol number; use port 0 for IP proto scans.
	key := CorrelationKey(dst.String(), s.srcIP.String(), int(proto), 0)
	ch := s.capture.Register(key)
	defer s.capture.Unregister(key)

	frame, err := s.builder.BuildRawIP(dst, proto, 64)
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
		if resp.Proto == "icmp" && resp.ICMP != nil {
			if resp.ICMP.Type == 3 && resp.ICMP.Code == 2 {
				// Protocol unreachable
				return scanner.StateClosed, "icmp-proto-unreach", rtt, nil
			}
			if resp.ICMP.Type == 3 {
				return scanner.StateFiltered, "icmp-unreach", rtt, nil
			}
		}
		// Any other response → the protocol is supported
		return scanner.StateOpen, "proto-response", rtt, nil
	}
}
