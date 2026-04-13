package protocol

import (
	"context"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// DNSTunnelProber uses DNS queries as a covert channel to probe host availability.
type DNSTunnelProber struct {
	resolver string // DNS server address "ip:port"
}

// NewDNSTunnelProber creates a DNSTunnelProber targeting the given resolver.
// If resolver is empty, "8.8.8.8:53" is used.
func NewDNSTunnelProber(resolver string) *DNSTunnelProber {
	if resolver == "" {
		resolver = "8.8.8.8:53"
	}
	return &DNSTunnelProber{resolver: resolver}
}

// Probe sends a DNS A-record query that encodes the target IP as a hostname
// query. Used to test if a host is reachable via the DNS resolution path.
//
// The query encodes target as a label, e.g. "192.168.1.1" becomes
// "192-168-1-1.probe.portex.local." — any positive answer (including NXDOMAIN)
// indicates the DNS server is reachable via the configured resolver path.
func (d *DNSTunnelProber) Probe(ctx context.Context, target string) (bool, error) {
	// Encode the target IP as a safe DNS label (replace dots with dashes).
	label := strings.ReplaceAll(target, ".", "-")
	qname := fmt.Sprintf("%s.probe.portex.local.", label)

	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeA)
	msg.RecursionDesired = true

	client := &dns.Client{}

	reply, _, err := client.ExchangeContext(ctx, msg, d.resolver)
	if err != nil {
		// A network error means the DNS path is not reachable.
		return false, nil //nolint:nilerr // intentional: treat DNS errors as unreachable
	}

	// Any non-error reply (NXDOMAIN, NOERROR, REFUSED) indicates the resolver
	// was reachable, which is sufficient for a covert-channel connectivity check.
	return reply != nil, nil
}
