package packet

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/m4rvxpn/portex/internal/scanner"
)

// IdleScanner performs Idle/Zombie scans (-sI).
// Exploits the IP ID side-channel: probe zombie's IP ID, send spoofed SYN
// to target (as if from zombie), probe zombie again.
// IPID increment of 2 → target port open. Increment of 1 → closed.
type IdleScanner struct {
	builder    *PacketBuilder
	rawSock    *RawSocket
	capture    *Capturer
	srcIP      net.IP
	zombieIP   net.IP
	zombiePort int
}

// NewIdleScanner creates a new IdleScanner.
func NewIdleScanner(builder *PacketBuilder, rawSock *RawSocket, capture *Capturer, srcIP, zombieIP net.IP, zombiePort int) *IdleScanner {
	return &IdleScanner{
		builder:    builder,
		rawSock:    rawSock,
		capture:    capture,
		srcIP:      srcIP,
		zombieIP:   zombieIP,
		zombiePort: zombiePort,
	}
}

// GetZombieIPID sends a SYN+ACK to the zombie's closed port to elicit a RST,
// then reads the RST and extracts the IP ID field.
func (s *IdleScanner) GetZombieIPID(ctx context.Context) (uint16, error) {
	srcPort := randEphemeralPort()

	key := CorrelationKey(s.zombieIP.String(), s.srcIP.String(), s.zombiePort, srcPort)
	ch := s.capture.Register(key)
	defer s.capture.Unregister(key)

	frame, err := s.builder.BuildTCP(s.zombieIP, s.zombiePort, srcPort, TCPFlags{SYN: true, ACK: true}, 64, nil)
	if err != nil {
		return 0, fmt.Errorf("build SYN+ACK to zombie: %w", err)
	}

	if _, err := s.rawSock.Write(frame); err != nil {
		return 0, fmt.Errorf("send SYN+ACK to zombie: %w", err)
	}

	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	select {
	case <-probeCtx.Done():
		return 0, fmt.Errorf("no RST from zombie (timeout)")
	case resp := <-ch:
		if resp.Proto == "tcp" && resp.Flags.RST {
			return resp.IPID, nil
		}
		return 0, fmt.Errorf("unexpected response from zombie: proto=%s", resp.Proto)
	}
}

// ScanPort implements the three-phase idle scan:
//  1. Probe zombie to get baseline IP ID.
//  2. Send spoofed SYN to target (src = zombieIP).
//  3. Probe zombie again and compare IP ID delta.
func (s *IdleScanner) ScanPort(ctx context.Context, dst net.IP, dstPort int) (scanner.PortState, string, time.Duration, error) {
	start := time.Now()

	// Phase 1: get zombie's initial IP ID.
	ipid1, err := s.GetZombieIPID(ctx)
	if err != nil {
		return scanner.StateUnknown, "zombie-probe-fail", 0, err
	}

	// Phase 2: send spoofed SYN to target pretending to be the zombie.
	spoofedFrame, err := s.buildSpoofedSYN(dst, dstPort, randEphemeralPort())
	if err != nil {
		return scanner.StateUnknown, "build-spoof-error", 0, err
	}

	if _, err := s.rawSock.Write(spoofedFrame); err != nil {
		return scanner.StateUnknown, "send-error", 0, err
	}

	// Brief pause to let the target respond to the zombie.
	time.Sleep(100 * time.Millisecond)

	// Phase 3: probe zombie again.
	ipid2, err := s.GetZombieIPID(ctx)
	if err != nil {
		return scanner.StateUnknown, "zombie-probe-fail-2", 0, err
	}

	rtt := time.Since(start)
	delta := int(ipid2) - int(ipid1)
	// Handle wraparound
	if delta < 0 {
		delta += 65536
	}

	switch {
	case delta >= 2:
		return scanner.StateOpen, "ipid-increment-2", rtt, nil
	case delta == 1:
		return scanner.StateClosed, "ipid-increment-1", rtt, nil
	default:
		return scanner.StateFiltered, "ipid-no-change", rtt, nil
	}
}

// buildSpoofedSYN builds a TCP SYN frame with the zombie's IP as the source.
// A fresh PacketBuilder is constructed pointing at the zombie IP so the IP
// source field is correctly spoofed on the wire.
func (s *IdleScanner) buildSpoofedSYN(dst net.IP, dstPort, srcPort int) ([]byte, error) {
	// Construct a lightweight builder using the zombie IP as source.
	// We must NOT copy s.builder (sync.Pool contains noCopy); instead we build
	// a new PacketBuilder initialising its pool.New inline.
	spoof := &PacketBuilder{
		srcIP:  s.zombieIP,
		srcMAC: s.builder.srcMAC,
		gwMAC:  s.builder.gwMAC,
	}
	spoof.bufPool.New = func() interface{} {
		return gopacket.NewSerializeBuffer()
	}
	return spoof.BuildTCP(dst, dstPort, srcPort, TCPFlags{SYN: true}, 64, nil)
}
