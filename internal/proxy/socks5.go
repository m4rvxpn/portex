package proxy

import (
	"context"
	"fmt"
	"net"

	"golang.org/x/net/proxy"
)

// SOCKS5Dialer dials connections through a SOCKS5 proxy.
type SOCKS5Dialer struct {
	dialer proxy.Dialer
	addr   string
}

// NewSOCKS5Dialer creates a SOCKS5 dialer for the given proxy address.
// addr format: "host:port"
func NewSOCKS5Dialer(addr string) (*SOCKS5Dialer, error) {
	d, err := proxy.SOCKS5("tcp", addr, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("create SOCKS5 dialer for %q: %w", addr, err)
	}
	return &SOCKS5Dialer{dialer: d, addr: addr}, nil
}

// DialContext opens a connection through the SOCKS5 proxy.
func (d *SOCKS5Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	// golang.org/x/net/proxy.Dialer does not have DialContext; use context-aware
	// wrapper if the underlying dialer implements it, otherwise fall back.
	type contextDialer interface {
		DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	}
	if cd, ok := d.dialer.(contextDialer); ok {
		return cd.DialContext(ctx, network, addr)
	}

	// Fallback: run Dial in a goroutine so we can honour ctx cancellation.
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := d.dialer.Dial(network, addr)
		ch <- result{conn, err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		return r.conn, r.err
	}
}
