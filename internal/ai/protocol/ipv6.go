package protocol

import (
	"net"
)

// IPv6Prober handles IPv6 dual-stack probing.
type IPv6Prober struct{}

// NewIPv6Prober creates a new IPv6Prober.
func NewIPv6Prober() *IPv6Prober { return &IPv6Prober{} }

// IsIPv6 returns true if target is a valid IPv6 address.
func (p *IPv6Prober) IsIPv6(target string) bool {
	ip := net.ParseIP(target)
	if ip == nil {
		return false
	}
	return ip.To4() == nil && ip.To16() != nil
}

// ResolveIPv6 resolves the hostname to an IPv6 address.
// Returns the first IPv6 address found, or an error if none is available.
func (p *IPv6Prober) ResolveIPv6(host string) (net.IP, error) {
	addrs, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		if addr.To4() == nil && addr.To16() != nil {
			return addr, nil
		}
	}
	return nil, &net.DNSError{
		Err:  "no IPv6 address found",
		Name: host,
	}
}
