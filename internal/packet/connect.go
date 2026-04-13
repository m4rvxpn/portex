package packet

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/m4rvxpn/portex/internal/scanner"
)

// ConnectScanner performs TCP connect scans (-sT).
// No raw sockets needed — falls back to full TCP connect().
type ConnectScanner struct {
	timeout time.Duration
	dialer  net.Dialer
}

// NewConnectScanner creates a new ConnectScanner with the given timeout.
func NewConnectScanner(timeout time.Duration) *ConnectScanner {
	return &ConnectScanner{
		timeout: timeout,
		dialer:  net.Dialer{Timeout: timeout},
	}
}

// Scan performs a full TCP connect to dst:dstPort.
func (s *ConnectScanner) Scan(ctx context.Context, dst net.IP, dstPort int) (state scanner.PortState, reason string, rtt time.Duration, err error) {
	addr := fmt.Sprintf("%s:%d", dst.String(), dstPort)
	start := time.Now()
	conn, dialErr := s.dialer.DialContext(ctx, "tcp", addr)
	rtt = time.Since(start)

	if dialErr == nil {
		conn.Close()
		return scanner.StateOpen, "open", rtt, nil
	}

	// Distinguish refused (closed) vs filtered (timeout / no route)
	if netErr, ok := dialErr.(net.Error); ok && netErr.Timeout() {
		return scanner.StateFiltered, "no-response", rtt, nil
	}
	// connection refused = closed
	return scanner.StateClosed, "conn-refused", rtt, nil
}
