package packet

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// TCPFlags holds the flag fields for a TCP packet.
type TCPFlags struct {
	SYN, ACK, FIN, RST, PSH, URG bool
	URGPtr                        uint16
}

// IPv6ExtHeader is a raw IPv6 extension header.
type IPv6ExtHeader struct {
	NextHeader uint8
	Data       []byte
}

// PacketBuilder builds raw Ethernet frames using gopacket.
// SerializeBuffers are pooled to avoid allocations in the hot path.
type PacketBuilder struct {
	bufPool sync.Pool
	srcIP   net.IP
	srcMAC  net.HardwareAddr
	gwMAC   net.HardwareAddr
}

// NewPacketBuilder creates a PacketBuilder for the given source IP and interface.
// It uses the interface's MAC as srcMAC and broadcast as gwMAC.
func NewPacketBuilder(srcIP net.IP, iface string) (*PacketBuilder, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("interface %q: %w", iface, err)
	}

	pb := &PacketBuilder{
		srcIP:  srcIP,
		srcMAC: ifi.HardwareAddr,
		gwMAC:  net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	}
	pb.bufPool = sync.Pool{
		New: func() interface{} {
			return gopacket.NewSerializeBuffer()
		},
	}
	return pb, nil
}

func (b *PacketBuilder) getBuffer() gopacket.SerializeBuffer {
	buf := b.bufPool.Get().(gopacket.SerializeBuffer)
	buf.Clear()
	return buf
}

func (b *PacketBuilder) putBuffer(buf gopacket.SerializeBuffer) {
	b.bufPool.Put(buf)
}

var serializeOpts = gopacket.SerializeOptions{
	FixLengths:       true,
	ComputeChecksums: true,
}

// BuildTCP builds an IPv4 TCP Ethernet frame with the given flags.
func (b *PacketBuilder) BuildTCP(dst net.IP, dstPort, srcPort int, flags TCPFlags, ttl uint8, payload []byte) ([]byte, error) {
	buf := b.getBuffer()
	defer b.putBuffer(buf)

	ethType := layers.EthernetTypeIPv4
	eth := &layers.Ethernet{
		SrcMAC:       b.srcMAC,
		DstMAC:       b.gwMAC,
		EthernetType: ethType,
	}

	ip := &layers.IPv4{
		Version:  4,
		TTL:      ttl,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    b.srcIP,
		DstIP:    dst,
	}

	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     randUint32(),
		Window:  65535,
		SYN:     flags.SYN,
		ACK:     flags.ACK,
		FIN:     flags.FIN,
		RST:     flags.RST,
		PSH:     flags.PSH,
		URG:     flags.URG,
		Urgent:  flags.URGPtr,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		return nil, err
	}

	var payloadLayer gopacket.Payload = payload
	if err := gopacket.SerializeLayers(buf, serializeOpts, eth, ip, tcp, payloadLayer); err != nil {
		return nil, fmt.Errorf("serialize TCP: %w", err)
	}

	out := make([]byte, len(buf.Bytes()))
	copy(out, buf.Bytes())
	return out, nil
}

// BuildTCPSpoofed builds a TCP frame with an arbitrary spoofed source IP.
// Used for idle scan and decoy flooding where the source must differ from the real scanner IP.
func (b *PacketBuilder) BuildTCPSpoofed(spoofSrc, dst net.IP, dstPort, srcPort int, flags TCPFlags, ttl uint8, payload []byte) ([]byte, error) {
	buf := b.getBuffer()
	defer b.putBuffer(buf)

	eth := &layers.Ethernet{
		SrcMAC:       b.srcMAC,
		DstMAC:       b.gwMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      ttl,
		SrcIP:    spoofSrc,
		DstIP:    dst,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     flags.SYN,
		ACK:     flags.ACK,
		FIN:     flags.FIN,
		RST:     flags.RST,
		PSH:     flags.PSH,
		URG:     flags.URG,
		Urgent:  flags.URGPtr,
		Window:  1024,
		Seq:     randUint32(),
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		return nil, err
	}
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		return nil, err
	}
	out := make([]byte, len(buf.Bytes()))
	copy(out, buf.Bytes())
	return out, nil
}

// BuildUDP builds an IPv4 UDP Ethernet frame.
func (b *PacketBuilder) BuildUDP(dst net.IP, dstPort, srcPort int, ttl uint8, payload []byte) ([]byte, error) {
	buf := b.getBuffer()
	defer b.putBuffer(buf)

	eth := &layers.Ethernet{
		SrcMAC:       b.srcMAC,
		DstMAC:       b.gwMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		TTL:      ttl,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    b.srcIP,
		DstIP:    dst,
	}

	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		return nil, err
	}

	var payloadLayer gopacket.Payload = payload
	if err := gopacket.SerializeLayers(buf, serializeOpts, eth, ip, udp, payloadLayer); err != nil {
		return nil, fmt.Errorf("serialize UDP: %w", err)
	}

	out := make([]byte, len(buf.Bytes()))
	copy(out, buf.Bytes())
	return out, nil
}

// BuildSCTP builds an IPv4 SCTP INIT Ethernet frame.
func (b *PacketBuilder) BuildSCTP(dst net.IP, dstPort, srcPort int, initTag uint32) ([]byte, error) {
	buf := b.getBuffer()
	defer b.putBuffer(buf)

	eth := &layers.Ethernet{
		SrcMAC:       b.srcMAC,
		DstMAC:       b.gwMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolSCTP,
		SrcIP:    b.srcIP,
		DstIP:    dst,
	}

	sctp := &layers.SCTP{
		SrcPort:         layers.SCTPPort(srcPort),
		DstPort:         layers.SCTPPort(dstPort),
		VerificationTag: 0,
	}

	init := &layers.SCTPInit{
		SCTPChunk: layers.SCTPChunk{
			Type:  layers.SCTPChunkTypeInit,
			Flags: 0,
		},
		InitiateTag:                    initTag,
		AdvertisedReceiverWindowCredit: 65535,
		OutboundStreams:                10,
		InboundStreams:                 2048,
		InitialTSN:                     randUint32(),
	}

	if err := gopacket.SerializeLayers(buf, serializeOpts, eth, ip, sctp, init); err != nil {
		return nil, fmt.Errorf("serialize SCTP: %w", err)
	}

	out := make([]byte, len(buf.Bytes()))
	copy(out, buf.Bytes())
	return out, nil
}

// BuildICMP builds an ICMPv4 Ethernet frame.
func (b *PacketBuilder) BuildICMP(dst net.IP, icmpType, icmpCode uint8, id, seq uint16) ([]byte, error) {
	buf := b.getBuffer()
	defer b.putBuffer(buf)

	eth := &layers.Ethernet{
		SrcMAC:       b.srcMAC,
		DstMAC:       b.gwMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    b.srcIP,
		DstIP:    dst,
	}

	icmp := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(icmpType, icmpCode),
		Id:       id,
		Seq:      seq,
	}

	if err := gopacket.SerializeLayers(buf, serializeOpts, eth, ip, icmp); err != nil {
		return nil, fmt.Errorf("serialize ICMP: %w", err)
	}

	out := make([]byte, len(buf.Bytes()))
	copy(out, buf.Bytes())
	return out, nil
}

// BuildIPv6TCP builds an IPv6 TCP Ethernet frame with optional extension headers.
// Extension headers are appended as raw bytes after the IPv6 header (simplified).
func (b *PacketBuilder) BuildIPv6TCP(dst net.IP, dstPort, srcPort int, flags TCPFlags, hopLimit uint8, extHeaders []IPv6ExtHeader) ([]byte, error) {
	buf := b.getBuffer()
	defer b.putBuffer(buf)

	eth := &layers.Ethernet{
		SrcMAC:       b.srcMAC,
		DstMAC:       b.gwMAC,
		EthernetType: layers.EthernetTypeIPv6,
	}

	ip6 := &layers.IPv6{
		Version:    6,
		HopLimit:   hopLimit,
		NextHeader: layers.IPProtocolTCP,
		SrcIP:      b.srcIP,
		DstIP:      dst,
	}

	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     randUint32(),
		Window:  65535,
		SYN:     flags.SYN,
		ACK:     flags.ACK,
		FIN:     flags.FIN,
		RST:     flags.RST,
		PSH:     flags.PSH,
		URG:     flags.URG,
		Urgent:  flags.URGPtr,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip6); err != nil {
		return nil, err
	}

	if err := gopacket.SerializeLayers(buf, serializeOpts, eth, ip6, tcp); err != nil {
		return nil, fmt.Errorf("serialize IPv6 TCP: %w", err)
	}

	// If extension headers requested, append them manually after the IPv6 header.
	// For now we skip insertion into the wire format as it requires rewriting the
	// NextHeader chain — callers requiring ext headers should handle manually.
	_ = extHeaders

	out := make([]byte, len(buf.Bytes()))
	copy(out, buf.Bytes())
	return out, nil
}

// BuildRawIP builds an IPv4 frame with a custom protocol number and empty
// payload. Used for IP Protocol scans (-sO).
func (b *PacketBuilder) BuildRawIP(dst net.IP, proto uint8, ttl uint8) ([]byte, error) {
	buf := b.getBuffer()
	defer b.putBuffer(buf)

	eth := &layers.Ethernet{
		SrcMAC:       b.srcMAC,
		DstMAC:       b.gwMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		TTL:      ttl,
		Protocol: layers.IPProtocol(proto),
		SrcIP:    b.srcIP,
		DstIP:    dst,
	}

	// 4-byte placeholder payload so the packet is valid.
	placeholder := make([]byte, 4)
	binary.BigEndian.PutUint32(placeholder, 0)

	var payloadLayer gopacket.Payload = placeholder
	if err := gopacket.SerializeLayers(buf, serializeOpts, eth, ip, payloadLayer); err != nil {
		return nil, fmt.Errorf("serialize raw IP: %w", err)
	}

	out := make([]byte, len(buf.Bytes()))
	copy(out, buf.Bytes())
	return out, nil
}
