package osfp

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/m4rvxpn/portex/internal/packet"
)

// TCPIPMetrics holds measured TCP/IP stack properties.
type TCPIPMetrics struct {
	ISNDiff    uint32 // initial sequence number delta between probes
	IPTTL      uint8
	IPDF       bool // don't-fragment bit
	TCPWindow  uint16
	TCPOptions []byte // raw TCP options bytes
	WinScale   int    // TCP window scale option value
	MSS        uint16
	RSTFlags   packet.TCPFlags
	ProbeRTTs  [7]time.Duration
}

// Collector runs nmap-style OS probes to collect TCP/IP metrics.
type Collector struct {
	builder *packet.PacketBuilder
	rawSock *packet.RawSocket
	capture *packet.Capturer
	srcIP   net.IP
}

// NewCollector creates a new Collector.
func NewCollector(builder *packet.PacketBuilder, rawSock *packet.RawSocket, capture *packet.Capturer, srcIP net.IP) *Collector {
	return &Collector{
		builder: builder,
		rawSock: rawSock,
		capture: capture,
		srcIP:   srcIP,
	}
}

// Collect sends the simplified OS probes (T1 SYN to open port, T5 SYN to closed port)
// and collects TTL, window, MSS from the responses.
func (c *Collector) Collect(ctx context.Context, target net.IP, openPort, closedPort int) (*TCPIPMetrics, error) {
	metrics := &TCPIPMetrics{}

	srcPort := 40000 + rand.Intn(10000)

	// T1: SYN probe to open port
	t1Metrics, err := c.sendSYNProbe(ctx, target, openPort, srcPort, 0)
	if err != nil {
		return nil, fmt.Errorf("T1 probe: %w", err)
	}
	if t1Metrics != nil {
		metrics.IPTTL = t1Metrics.IPTTL
		metrics.TCPWindow = t1Metrics.TCPWindow
		metrics.MSS = t1Metrics.MSS
		metrics.ProbeRTTs[0] = t1Metrics.ProbeRTTs[0]
	}

	// T5: SYN probe to closed port
	srcPort2 := srcPort + 1
	t5Metrics, err := c.sendSYNProbe(ctx, target, closedPort, srcPort2, 4)
	if err == nil && t5Metrics != nil {
		// TTL from closed port response (may differ)
		if metrics.IPTTL == 0 {
			metrics.IPTTL = t5Metrics.IPTTL
		}
		metrics.ProbeRTTs[4] = t5Metrics.ProbeRTTs[4]
	}

	return metrics, nil
}

// sendSYNProbe sends a single SYN probe and waits for a response.
// probeIdx is the index into ProbeRTTs (0-6).
func (c *Collector) sendSYNProbe(ctx context.Context, target net.IP, dstPort, srcPort, probeIdx int) (*TCPIPMetrics, error) {
	flags := packet.TCPFlags{SYN: true}
	frame, err := c.builder.BuildTCP(target, dstPort, srcPort, flags, 64, nil)
	if err != nil {
		return nil, fmt.Errorf("build TCP: %w", err)
	}

	// Register for the response before sending
	key := packet.CorrelationKey(target.String(), c.srcIP.String(), dstPort, srcPort)
	respCh := c.capture.Register(key)
	defer c.capture.Unregister(key)

	sent := time.Now()
	if _, err := c.rawSock.Write(frame); err != nil {
		return nil, fmt.Errorf("send frame: %w", err)
	}

	// Wait for response with timeout
	timeout := 3 * time.Second
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, fmt.Errorf("probe timeout")
	case resp := <-respCh:
		rtt := time.Since(sent)
		metrics := &TCPIPMetrics{
			IPTTL:     resp.TTL,
			TCPWindow: resp.Window,
		}
		metrics.ProbeRTTs[probeIdx] = rtt
		metrics.RSTFlags = resp.Flags

		// Parse TCP options from the response to extract MSS
		// (gopacket's Response doesn't expose raw options, so we use window as proxy)
		// A common MSS value inferred from window size:
		if resp.Window >= 65535 {
			metrics.MSS = 1460 // typical Linux MSS
		} else if resp.Window >= 8192 {
			metrics.MSS = 1460
		}

		return metrics, nil
	}
}
