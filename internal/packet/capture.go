package packet

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ICMPInfo holds ICMP-specific fields from a response.
type ICMPInfo struct {
	Type         uint8
	Code         uint8
	InnerDstPort int
	InnerProto   uint8
}

// Response is a captured response packet parsed into key fields.
type Response struct {
	SrcIP   net.IP
	SrcPort int
	DstIP   net.IP
	DstPort int
	Flags   TCPFlags
	TTL     uint8
	Window  uint16
	Payload []byte
	ICMP    *ICMPInfo
	Proto   string // "tcp", "udp", "icmp", "sctp"
	IPProto uint8  // IP protocol number (for -sO)
	IPID    uint16 // IP identification field (for idle scan)
	RecvAt  time.Time
}

// Capturer binds a libpcap handle and routes responses to waiting goroutines.
type Capturer struct {
	handle  *pcap.Handle
	pending sync.Map // key: string → chan Response
	iface   string
}

// NewCapturer creates a new Capturer on the given interface.
func NewCapturer(iface string) (*Capturer, error) {
	handle, err := pcap.OpenLive(iface, 65535, false, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("pcap.OpenLive(%q): %w", iface, err)
	}
	if err := handle.SetBPFFilter("tcp or udp or icmp or sctp"); err != nil {
		handle.Close()
		return nil, fmt.Errorf("set BPF filter: %w", err)
	}
	return &Capturer{handle: handle, iface: iface}, nil
}

// Start begins capturing packets in a background goroutine. Stops on ctx cancel.
func (c *Capturer) Start(ctx context.Context) error {
	src := gopacket.NewPacketSource(c.handle, c.handle.LinkType())
	src.NoCopy = true

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case pkt, ok := <-src.Packets():
				if !ok {
					return
				}
				c.processPacket(pkt)
			}
		}
	}()
	return nil
}

// Register subscribes for responses matching the given key.
// Returns a channel that will receive at most one matching Response.
func (c *Capturer) Register(key string) <-chan Response {
	ch := make(chan Response, 1)
	c.pending.Store(key, ch)
	return ch
}

// Unregister removes a subscription.
func (c *Capturer) Unregister(key string) {
	c.pending.Delete(key)
}

// Close shuts down the pcap handle.
func (c *Capturer) Close() error {
	c.handle.Close()
	return nil
}

// CorrelationKey builds the hashmap key for a probe.
// Format: "srcIP:srcPort:dstIP:dstPort"
func CorrelationKey(srcIP, dstIP string, srcPort, dstPort int) string {
	return fmt.Sprintf("%s:%d:%s:%d", srcIP, srcPort, dstIP, dstPort)
}

// processPacket dispatches a captured packet to the matching registered channel.
// This must never block.
func (c *Capturer) processPacket(pkt gopacket.Packet) {
	now := time.Now()

	// Extract IP layer
	var srcIP, dstIP net.IP
	var ttl uint8
	var ipID uint16
	var ipProto uint8

	if ip4 := pkt.Layer(layers.LayerTypeIPv4); ip4 != nil {
		ip := ip4.(*layers.IPv4)
		srcIP = ip.SrcIP
		dstIP = ip.DstIP
		ttl = ip.TTL
		ipID = ip.Id
		ipProto = uint8(ip.Protocol)
	} else if ip6 := pkt.Layer(layers.LayerTypeIPv6); ip6 != nil {
		ip := ip6.(*layers.IPv6)
		srcIP = ip.SrcIP
		dstIP = ip.DstIP
		ttl = ip.HopLimit
		ipProto = uint8(ip.NextHeader)
	} else {
		return
	}

	resp := Response{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		TTL:     ttl,
		IPProto: ipProto,
		IPID:    ipID,
		RecvAt:  now,
	}

	// TCP response
	if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		resp.Proto = "tcp"
		resp.SrcPort = int(tcp.SrcPort)
		resp.DstPort = int(tcp.DstPort)
		resp.Window = tcp.Window
		resp.Flags = TCPFlags{
			SYN:    tcp.SYN,
			ACK:    tcp.ACK,
			FIN:    tcp.FIN,
			RST:    tcp.RST,
			PSH:    tcp.PSH,
			URG:    tcp.URG,
			URGPtr: tcp.Urgent,
		}
		if app := pkt.ApplicationLayer(); app != nil {
			resp.Payload = app.Payload()
		}
		// key: srcIP(target):srcPort(target_resp):dstIP(us):dstPort(our_src)
		key := CorrelationKey(srcIP.String(), dstIP.String(), resp.SrcPort, resp.DstPort)
		c.dispatch(key, resp)
		return
	}

	// UDP response
	if udpLayer := pkt.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		resp.Proto = "udp"
		resp.SrcPort = int(udp.SrcPort)
		resp.DstPort = int(udp.DstPort)
		if app := pkt.ApplicationLayer(); app != nil {
			resp.Payload = app.Payload()
		}
		key := CorrelationKey(srcIP.String(), dstIP.String(), resp.SrcPort, resp.DstPort)
		c.dispatch(key, resp)
		return
	}

	// ICMP response
	if icmpLayer := pkt.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		icmp := icmpLayer.(*layers.ICMPv4)
		resp.Proto = "icmp"
		icmpInfo := &ICMPInfo{
			Type: icmp.TypeCode.Type(),
			Code: icmp.TypeCode.Code(),
		}
		resp.ICMP = icmpInfo

		// For ICMP unreachable, parse the inner IP+transport header.
		if icmpInfo.Type == 3 {
			payload := icmp.LayerPayload()
			if len(payload) >= 20 {
				// Inner IP header: protocol at offset 9, dst at 16-20
				icmpInfo.InnerProto = payload[9]
				innerDstIP := net.IP(payload[16:20])
				var innerDstPort int
				// Transport header starts at offset IHL*4
				ihl := int(payload[0]&0x0f) * 4
				if len(payload) >= ihl+4 {
					innerDstPort = int(binary.BigEndian.Uint16(payload[ihl+2 : ihl+4]))
				}
				icmpInfo.InnerDstPort = innerDstPort
				// Dispatch to whoever is waiting for a response from target:innerDstPort
				// The key they registered: CorrelationKey(ourIP, targetIP, ourSrcPort, targetPort)
				// For ICMP unreachables we need to find the right waiter.
				// We dispatch on inner source port (our srcPort) → inner dst port (target port).
				var innerSrcPort int
				if len(payload) >= ihl+2 {
					innerSrcPort = int(binary.BigEndian.Uint16(payload[ihl : ihl+2]))
				}
				// key: srcIP(target):srcPort(target_port):dstIP(us):dstPort(our_srcPort)
				key := CorrelationKey(innerDstIP.String(), dstIP.String(), innerDstPort, innerSrcPort)
				c.dispatch(key, resp)
				return
			}
		}
		// Generic ICMP: dispatch by srcIP
		key := CorrelationKey(srcIP.String(), dstIP.String(), 0, 0)
		c.dispatch(key, resp)
		return
	}

	// SCTP response
	if sctpLayer := pkt.Layer(layers.LayerTypeSCTP); sctpLayer != nil {
		sctp := sctpLayer.(*layers.SCTP)
		resp.Proto = "sctp"
		resp.SrcPort = int(sctp.SrcPort)
		resp.DstPort = int(sctp.DstPort)
		key := CorrelationKey(srcIP.String(), dstIP.String(), resp.SrcPort, resp.DstPort)
		c.dispatch(key, resp)
		return
	}
}

// dispatch sends resp to the channel registered under key (non-blocking).
func (c *Capturer) dispatch(key string, resp Response) {
	if val, ok := c.pending.Load(key); ok {
		ch := val.(chan Response)
		select {
		case ch <- resp:
		default:
		}
	}
}
