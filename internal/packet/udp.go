package packet

import (
	"context"
	"net"
	"time"

	"github.com/m4rvxpn/portex/internal/scanner"
)

// UDPScanner performs UDP scans (-sU).
// Open: any UDP response. Closed: ICMP port unreachable (type 3 code 3).
// Filtered: ICMP admin/host prohibit or no response after retries.
// Open|Filtered: no response (default UDP assumption).
type UDPScanner struct {
	builder *PacketBuilder
	rawSock *RawSocket
	capture *Capturer
	srcIP   net.IP
}

// NewUDPScanner creates a new UDPScanner.
func NewUDPScanner(builder *PacketBuilder, rawSock *RawSocket, capture *Capturer, srcIP net.IP) *UDPScanner {
	return &UDPScanner{
		builder: builder,
		rawSock: rawSock,
		capture: capture,
		srcIP:   srcIP,
	}
}

// getUDPPayload returns a service-specific probe payload for well-known UDP ports.
func getUDPPayload(port int) []byte {
	switch port {
	case 53:
		// Minimal DNS query: version.bind (CHAOS class TXT)
		return []byte{
			0x00, 0x01, // transaction ID
			0x00, 0x00, // flags: standard query
			0x00, 0x01, // QDCOUNT: 1
			0x00, 0x00, // ANCOUNT: 0
			0x00, 0x00, // NSCOUNT: 0
			0x00, 0x00, // ARCOUNT: 0
			// QNAME: version.bind
			0x07, 'v', 'e', 'r', 's', 'i', 'o', 'n',
			0x04, 'b', 'i', 'n', 'd',
			0x00,       // null terminator
			0x00, 0x10, // QTYPE: TXT
			0x00, 0x03, // QCLASS: CHAOS
		}
	case 161:
		// SNMPv1 get-request for sysDescr.0 (OID 1.3.6.1.2.1.1.1.0)
		return []byte{
			0x30, 0x26, // SEQUENCE
			0x02, 0x01, 0x00, // INTEGER: version = 0 (SNMPv1)
			0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c', // OCTET STRING: community = "public"
			0xa0, 0x19, // GetRequest PDU
			0x02, 0x01, 0x01, // request-id = 1
			0x02, 0x01, 0x00, // error-status = 0
			0x02, 0x01, 0x00, // error-index = 0
			0x30, 0x0e, // VarBindList
			0x30, 0x0c, // VarBind
			0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // OID: 1.3.6.1.2.1.1.1.0
			0x05, 0x00, // NULL
		}
	case 123:
		// NTP v2 client request (48 bytes)
		pkt := make([]byte, 48)
		pkt[0] = 0x1b // LI=0, VN=3, Mode=3 (client)
		return pkt
	default:
		return nil
	}
}

// Scan performs a UDP scan against dst:dstPort.
func (s *UDPScanner) Scan(ctx context.Context, dst net.IP, dstPort, srcPort int, ttl uint8) (scanner.PortState, string, time.Duration, error) {
	if srcPort == 0 {
		srcPort = randEphemeralPort()
	}
	if ttl == 0 {
		ttl = 64
	}

	payload := getUDPPayload(dstPort)

	key := CorrelationKey(dst.String(), s.srcIP.String(), dstPort, srcPort)
	ch := s.capture.Register(key)
	defer s.capture.Unregister(key)

	frame, err := s.builder.BuildUDP(dst, dstPort, srcPort, ttl, payload)
	if err != nil {
		return scanner.StateUnknown, "build-error", 0, err
	}

	sent := time.Now()
	if _, err := s.rawSock.Write(frame); err != nil {
		return scanner.StateUnknown, "send-error", 0, err
	}

	select {
	case <-ctx.Done():
		// UDP timeout → assume open|filtered
		return scanner.StateOpenFiltered, "no-response", 0, nil
	case resp := <-ch:
		rtt := resp.RecvAt.Sub(sent)
		if resp.Proto == "icmp" && resp.ICMP != nil {
			switch {
			case resp.ICMP.Type == 3 && resp.ICMP.Code == 3:
				// ICMP port unreachable → closed
				return scanner.StateClosed, "icmp-port-unreach", rtt, nil
			case resp.ICMP.Type == 3:
				// Other ICMP unreachable (admin, host, etc.) → filtered
				return scanner.StateFiltered, "icmp-unreach", rtt, nil
			}
		}
		if resp.Proto == "udp" {
			return scanner.StateOpen, "udp-response", rtt, nil
		}
		return scanner.StateOpenFiltered, "unexpected", rtt, nil
	}
}
