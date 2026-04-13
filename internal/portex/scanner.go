// Package portex provides the top-level PortexScanner that wires together the
// scanner engine and packet layer into a full scanning orchestrator.
package portex

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/m4rvxpn/portex/internal/config"
	"github.com/m4rvxpn/portex/internal/packet"
	"github.com/m4rvxpn/portex/internal/scanner"
)

// Scanner is the top-level interface.
type Scanner interface {
	Scan(ctx context.Context) (*scanner.ScanResult, error)
	ScanStream(ctx context.Context, out chan<- scanner.PortResult) error
}

// PortexScanner is the main scanner implementation.
type PortexScanner struct {
	cfg     *config.Config
	engine  *scanner.Engine
	capture *packet.Capturer
	builder *packet.PacketBuilder
	rawSock *packet.RawSocket
	srcIP   net.IP
	iface   string
}

// New creates a new PortexScanner from the given config.
// It detects the default network interface if cfg.Interface is empty.
// It opens the raw socket and libpcap handle.
func New(cfg *config.Config) (*PortexScanner, error) {
	iface := cfg.Interface
	var srcIP net.IP

	if iface == "" {
		var err error
		iface, srcIP, err = detectInterface()
		if err != nil {
			return nil, fmt.Errorf("detect interface: %w", err)
		}
	} else {
		// Resolve source IP from the specified interface.
		ifi, err := net.InterfaceByName(iface)
		if err != nil {
			return nil, fmt.Errorf("interface %q: %w", iface, err)
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			return nil, fmt.Errorf("interface addrs: %w", err)
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.To4() != nil {
				srcIP = ip.To4()
				break
			}
		}
		if srcIP == nil {
			return nil, fmt.Errorf("no IPv4 address on interface %q", iface)
		}
	}

	// Open the pcap capturer.
	capture, err := packet.NewCapturer(iface)
	if err != nil {
		return nil, fmt.Errorf("open capturer on %q: %w", iface, err)
	}

	// Open raw socket (requires CAP_NET_RAW).
	rawSock, err := packet.OpenRaw(iface)
	if err != nil {
		_ = capture.Close()
		return nil, fmt.Errorf("open raw socket: %w (run as root or with CAP_NET_RAW)", err)
	}

	builder, err := packet.NewPacketBuilder(srcIP, iface)
	if err != nil {
		_ = rawSock.Close()
		_ = capture.Close()
		return nil, fmt.Errorf("create packet builder: %w", err)
	}

	// Build the dispatch function that closes over packet-layer resources.
	dispatchFn := makeDispatchFunc(cfg, capture, builder, rawSock, srcIP)

	engine := scanner.NewEngine(cfg, dispatchFn)

	return &PortexScanner{
		cfg:     cfg,
		engine:  engine,
		capture: capture,
		builder: builder,
		rawSock: rawSock,
		srcIP:   srcIP,
		iface:   iface,
	}, nil
}

// Scan runs a full scan and returns all results when done.
func (s *PortexScanner) Scan(ctx context.Context) (*scanner.ScanResult, error) {
	result := &scanner.ScanResult{
		ScanID:    uuid.New().String(),
		SessionID: s.cfg.PhantomSessionID,
		StartTime: time.Now(),
		Targets:   s.cfg.Targets,
	}

	out := make(chan scanner.PortResult, 1000)
	if err := s.ScanStream(ctx, out); err != nil {
		return nil, err
	}
	for pr := range out {
		result.Ports = append(result.Ports, pr)
		result.TotalPorts++
		if pr.State == scanner.StateOpen {
			result.OpenPorts++
		}
	}
	result.EndTime = time.Now()
	result.Stats = s.engine.Stats()
	return result, nil
}

// ScanStream runs a scan and streams PortResults to the out channel as they arrive.
func (s *PortexScanner) ScanStream(ctx context.Context, out chan<- scanner.PortResult) error {
	probes, err := s.buildProbes()
	if err != nil {
		return fmt.Errorf("build probes: %w", err)
	}

	// Start the engine (goroutine pool + capturer).
	s.engine.Start(ctx)
	if s.capture != nil {
		_ = s.capture.Start(ctx)
	}

	// Feed probes from a dedicated goroutine so Submit doesn't block the caller.
	go func() {
		for _, p := range probes {
			if ctx.Err() != nil {
				break
			}
			_ = s.engine.Submit(p)
		}
		// Signal no more probes.
		s.engine.Drain()
	}()

	// Forward results to out.
	go func() {
		defer close(out)
		for pr := range s.engine.Results() {
			select {
			case out <- pr:
			case <-ctx.Done():
				return
			}
		}
	}()

	return nil
}

// Close releases all resources (raw socket, pcap handle).
func (s *PortexScanner) Close() error {
	var errs []error
	if s.rawSock != nil {
		if err := s.rawSock.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if s.capture != nil {
		if err := s.capture.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("close errors: %v", errs)
	}
	return nil
}

// detectInterface returns the name of the default outbound interface and its
// primary IPv4 address. It dials a UDP socket to 8.8.8.8:53 (no actual
// packet is sent) to discover the default route, then matches the local
// address to an interface.
func detectInterface() (string, net.IP, error) {
	conn, err := net.Dial("udp4", "8.8.8.8:53")
	if err != nil {
		return "", nil, fmt.Errorf("udp dial for route detection: %w", err)
	}
	conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	srcIP := localAddr.IP.To4()
	if srcIP == nil {
		return "", nil, fmt.Errorf("could not determine IPv4 source address")
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return "", nil, fmt.Errorf("list interfaces: %w", err)
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.To4() != nil && ip.To4().Equal(srcIP) {
				return iface.Name, srcIP, nil
			}
		}
	}

	return "", nil, fmt.Errorf("no interface found with IP %s", srcIP)
}

// buildProbes expands cfg.Targets × cfg.Ports into a []Probe slice.
func (s *PortexScanner) buildProbes() ([]scanner.Probe, error) {
	ports, err := s.cfg.ParsePortSpec(s.cfg.Ports)
	if err != nil {
		return nil, fmt.Errorf("parse port spec: %w", err)
	}

	timing := scanner.GetTiming(int(s.cfg.Timing))
	mode := scanner.ScanMode(s.cfg.Mode)
	deadline := time.Now().Add(timing.HostTimeout)

	var probes []scanner.Probe

	for _, target := range s.cfg.Targets {
		hosts, err := expandTarget(target)
		if err != nil {
			return nil, fmt.Errorf("expand target %q: %w", target, err)
		}

		for _, host := range hosts {
			for _, port := range ports {
				probes = append(probes, scanner.Probe{
					Target:   host,
					Port:     port,
					Protocol: defaultProtocolForMode(mode),
					ScanMode: mode,
					Attempt:  0,
					Deadline: deadline,
				})
			}
		}
	}

	return probes, nil
}

// expandTarget returns the list of host strings for a given target expression.
// Supports: single IPs, CIDRs (e.g. "10.0.0.0/24"), and hostnames.
func expandTarget(target string) ([]string, error) {
	// Try CIDR first.
	if _, ipNet, err := net.ParseCIDR(target); err == nil {
		return expandCIDR(ipNet), nil
	}

	// Plain IP.
	if ip := net.ParseIP(target); ip != nil {
		return []string{ip.String()}, nil
	}

	// Hostname — return as-is; resolution happens at probe dispatch time.
	return []string{target}, nil
}

// expandCIDR returns all host addresses in the network (excluding network
// and broadcast addresses for IPv4, unless the prefix is /31 or /32).
func expandCIDR(ipNet *net.IPNet) []string {
	var hosts []string

	ip4 := ipNet.IP.To4()
	if ip4 == nil {
		// IPv6 — return the base address as a single entry for now.
		return []string{ipNet.IP.String()}
	}

	start := binary.BigEndian.Uint32(ip4)
	mask := binary.BigEndian.Uint32([]byte(ipNet.Mask))
	end := start | ^mask

	ones, bits := ipNet.Mask.Size()
	isHost := (bits - ones) <= 1 // /31 or /32: no network/broadcast exclusion

	for n := start; n <= end; n++ {
		if !isHost && (n == start || n == end) {
			continue
		}
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, n)
		hosts = append(hosts, net.IP(b).String())
	}
	return hosts
}

// defaultProtocolForMode returns the protocol string for a given scan mode.
func defaultProtocolForMode(mode scanner.ScanMode) string {
	switch mode {
	case scanner.ScanModeUDP:
		return "udp"
	case scanner.ScanModeSCTP:
		return "sctp"
	default:
		return "tcp"
	}
}

// makeDispatchFunc returns a DispatchFunc that routes a probe to the correct
// packet-layer scanner. This function closes over all packet resources so
// the scanner.Engine stays free of any direct packet dependency.
func makeDispatchFunc(cfg *config.Config, cap *packet.Capturer, builder *packet.PacketBuilder, rawSock *packet.RawSocket, srcIP net.IP) scanner.DispatchFunc {
	return func(ctx context.Context, p scanner.Probe) (scanner.PortResult, error) {
		// Resolve target IP.
		dstIP := net.ParseIP(p.Target)
		if dstIP == nil {
			addrs, err := net.LookupHost(p.Target)
			if err != nil || len(addrs) == 0 {
				return scanner.PortResult{
					Target:    p.Target,
					Port:      p.Port,
					Protocol:  p.Protocol,
					State:     scanner.StateUnknown,
					Reason:    "resolve-error",
					Timestamp: time.Now(),
				}, fmt.Errorf("resolve %q: %w", p.Target, err)
			}
			dstIP = net.ParseIP(addrs[0])
		}

		// Pick source port.
		srcPort := p.SrcPort
		if srcPort == 0 {
			srcPort = 32768 + rand.Intn(28232)
		}

		// Pick TTL.
		ttl := p.TTL
		if ttl == 0 {
			ttl = 64
		}

		var (
			state  scanner.PortState
			reason string
			rtt    time.Duration
			err    error
		)

		switch p.ScanMode {
		case scanner.ScanModeSYN, scanner.ScanModeStealth:
			s := packet.NewSYNScanner(builder, rawSock, cap, srcIP)
			state, reason, rtt, err = s.Scan(ctx, dstIP, p.Port, srcPort, ttl)

		case scanner.ScanModeACK:
			s := packet.NewACKScanner(builder, rawSock, cap, srcIP)
			state, reason, rtt, err = s.Scan(ctx, dstIP, p.Port, srcPort, ttl)

		case scanner.ScanModeFIN:
			s := packet.NewFINScanner(builder, rawSock, cap, srcIP)
			state, reason, rtt, err = s.Scan(ctx, dstIP, p.Port, srcPort, ttl)

		case scanner.ScanModeXMAS:
			s := packet.NewXMASScanner(builder, rawSock, cap, srcIP)
			state, reason, rtt, err = s.Scan(ctx, dstIP, p.Port, srcPort, ttl)

		case scanner.ScanModeNULL:
			s := packet.NewNULLScanner(builder, rawSock, cap, srcIP)
			state, reason, rtt, err = s.Scan(ctx, dstIP, p.Port, srcPort, ttl)

		case scanner.ScanModeWindow:
			s := packet.NewWindowScanner(builder, rawSock, cap, srcIP)
			state, reason, rtt, err = s.Scan(ctx, dstIP, p.Port, srcPort, ttl)

		case scanner.ScanModeMaimon:
			s := packet.NewMaimonScanner(builder, rawSock, cap, srcIP)
			state, reason, rtt, err = s.Scan(ctx, dstIP, p.Port, srcPort, ttl)

		case scanner.ScanModeUDP:
			s := packet.NewUDPScanner(builder, rawSock, cap, srcIP)
			state, reason, rtt, err = s.Scan(ctx, dstIP, p.Port, srcPort, ttl)

		case scanner.ScanModeSCTP:
			s := packet.NewSCTPScanner(builder, rawSock, cap, srcIP)
			state, reason, rtt, err = s.Scan(ctx, dstIP, p.Port, srcPort, rand.Uint32())

		case scanner.ScanModeIPProto:
			s := packet.NewIPProtoScanner(builder, rawSock, cap, srcIP)
			state, reason, rtt, err = s.ScanProto(ctx, dstIP, uint8(p.Port))

		case scanner.ScanModeIdle:
			zombieIP := net.ParseIP(cfg.ZombieHost)
			if zombieIP == nil {
				state = scanner.StateUnknown
				reason = "invalid-zombie-ip"
				err = fmt.Errorf("invalid zombie host: %q", cfg.ZombieHost)
				break
			}
			s := packet.NewIdleScanner(builder, rawSock, cap, srcIP, zombieIP, cfg.ZombiePort)
			state, reason, rtt, err = s.ScanPort(ctx, dstIP, p.Port)

		case scanner.ScanModeFTP:
			timing := scanner.GetTiming(int(cfg.Timing))
			s := packet.NewFTPScanner(cfg.FTPHost, cfg.FTPPort, timing.MaxRTT)
			state, reason, rtt, err = s.Scan(ctx, dstIP, p.Port)

		case scanner.ScanModeConnect:
			timing := scanner.GetTiming(int(cfg.Timing))
			s := packet.NewConnectScanner(timing.MaxRTT)
			state, reason, rtt, err = s.Scan(ctx, dstIP, p.Port)

		default:
			// Default: SYN scan.
			s := packet.NewSYNScanner(builder, rawSock, cap, srcIP)
			state, reason, rtt, err = s.Scan(ctx, dstIP, p.Port, srcPort, ttl)
		}

		proto := p.Protocol
		if proto == "" {
			proto = "tcp"
		}

		return scanner.PortResult{
			Target:    p.Target,
			Port:      p.Port,
			Protocol:  proto,
			State:     state,
			Reason:    reason,
			RTT:       rtt,
			Timestamp: time.Now(),
		}, err
	}
}
