package service

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"time"
)

// BannerGrabber grabs banners from open ports.
type BannerGrabber struct {
	timeout time.Duration
}

// NewBannerGrabber creates a new BannerGrabber with the given timeout.
func NewBannerGrabber(timeout time.Duration) *BannerGrabber {
	return &BannerGrabber{timeout: timeout}
}

// Grab connects to target:port and reads the initial banner (up to 4096 bytes).
// Tries plain TCP first, then TLS if tcp fails or port is in sslPorts.
func (g *BannerGrabber) Grab(ctx context.Context, target string, port int, proto string) ([]byte, error) {
	addr := fmt.Sprintf("%s:%d", target, port)

	// Try plain connection first
	banner, err := g.grabPlain(ctx, addr, proto)
	if err == nil && len(banner) > 0 {
		return banner, nil
	}

	// Try TLS
	tlsBanner, tlsErr := g.grabTLS(ctx, addr, target)
	if tlsErr == nil {
		return tlsBanner, nil
	}

	// Return plain result even if empty, or the original error
	if err == nil {
		return banner, nil
	}
	return nil, err
}

// GrabWithProbe sends a probe payload and reads the response.
func (g *BannerGrabber) GrabWithProbe(ctx context.Context, target string, port int, proto string, payload []byte) ([]byte, error) {
	addr := fmt.Sprintf("%s:%d", target, port)

	dialCtx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()

	var conn net.Conn
	var err error

	if proto == "udp" || proto == "UDP" {
		conn, err = (&net.Dialer{}).DialContext(dialCtx, "udp", addr)
	} else {
		conn, err = (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	defer conn.Close()

	deadline := time.Now().Add(g.timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("set deadline: %w", err)
	}

	if len(payload) > 0 {
		if _, err := conn.Write(payload); err != nil {
			return nil, fmt.Errorf("write probe: %w", err)
		}
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		if n == 0 {
			return nil, fmt.Errorf("read response: %w", err)
		}
	}
	return buf[:n], nil
}

// grabPlain attempts a plain TCP/UDP connection and reads the initial banner.
func (g *BannerGrabber) grabPlain(ctx context.Context, addr, proto string) ([]byte, error) {
	dialCtx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()

	var conn net.Conn
	var err error

	if proto == "udp" || proto == "UDP" {
		conn, err = (&net.Dialer{}).DialContext(dialCtx, "udp", addr)
	} else {
		conn, err = (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(g.timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		if n == 0 {
			return nil, err
		}
	}
	return buf[:n], nil
}

// grabTLS attempts a TLS connection and reads the initial banner.
func (g *BannerGrabber) grabTLS(ctx context.Context, addr, serverName string) ([]byte, error) {
	dialCtx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()

	tlsCfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // intentional for banner grabbing
		ServerName:         serverName,
	}

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{},
		Config:    tlsCfg,
	}

	conn, err := dialer.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tls dial: %w", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(g.timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		if n == 0 {
			return nil, err
		}
	}
	return buf[:n], nil
}
