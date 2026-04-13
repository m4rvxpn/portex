// Package proxy provides proxy-aware network dialers for Portex.
package proxy

import (
	"context"
	"net"
)

// Dialer is the interface for proxy-aware connection dialing.
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// Direct is a direct (no-proxy) dialer.
type Direct struct{}

// DialContext opens a connection directly without any proxy.
func (d *Direct) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, addr)
}
