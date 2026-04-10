// Package scanner contains core scanning types, engine primitives, and result models.
package scanner

import "time"

// PortState represents the interpreted state of a scanned port.
type PortState string

const (
	// StateOpen indicates the port is accepting connections.
	StateOpen PortState = "open"
	// StateClosed indicates the port is reachable but not accepting connections.
	StateClosed PortState = "closed"
	// StateFiltered indicates a firewall or filter is blocking probe packets.
	StateFiltered PortState = "filtered"
	// StateOpenFiltered means the port is either open or filtered; indeterminate.
	StateOpenFiltered PortState = "open|filtered"
	// StateUnreachable indicates the host did not respond to the probe at all.
	StateUnreachable PortState = "unreachable"
	// StateUnknown is used when the state cannot be determined.
	StateUnknown PortState = "unknown"
)

// PortResult is the result of scanning a single port on a single target.
type PortResult struct {
	// Target is the IP address or hostname that was scanned.
	Target string
	// Port is the TCP/UDP/SCTP port number.
	Port int
	// Protocol is one of "tcp", "udp", or "sctp".
	Protocol string
	// State is the interpreted port state.
	State PortState
	// Reason is the packet-level evidence for the state decision,
	// e.g. "syn-ack", "rst", "no-response", "icmp-unreach", "open".
	Reason string
	// RTT is the round-trip time measured for the probe response.
	RTT time.Duration
	// TTL is the IP time-to-live extracted from the response packet.
	TTL uint8
	// WindowSize is the TCP window size advertised in the response, if any.
	WindowSize uint16
	// Service holds service/version detection results (nil if not run).
	Service *ServiceMatch
	// OS holds OS fingerprint results (nil if not run).
	OS *OSMatch
	// ScriptOut maps script names to their text output.
	ScriptOut map[string]string
	// LLMEnrich holds optional post-scan LLM analysis (nil if not enabled).
	LLMEnrich *LLMEnrichment
	// Timestamp is when the probe result was recorded.
	Timestamp time.Time
}

// ServiceMatch holds service and version detection results for a port.
type ServiceMatch struct {
	// Service is the canonical service name, e.g. "http", "ssh".
	Service string
	// Version is the version string extracted from the banner.
	Version string
	// Product is the product name, e.g. "OpenSSH", "Apache httpd".
	Product string
	// OS is the OS inferred from the service banner, if any.
	OS string
	// CPE is the Common Platform Enumeration identifier.
	CPE string
	// Banner is the raw service banner text.
	Banner string
	// Probe is the name of the probe that elicited this match.
	Probe string
	// Conf is the confidence score in the range [1, 10].
	Conf int
}

// OSMatch holds operating system fingerprint results.
type OSMatch struct {
	// Name is the human-readable OS name, e.g. "Linux 5.15".
	Name string
	// Accuracy is the match confidence percentage in [0, 100].
	Accuracy int
	// CPE is the Common Platform Enumeration identifier for this OS.
	CPE string
	// Family is the OS family, e.g. "Linux", "Windows".
	Family string
	// Generation is the OS generation string, e.g. "2.6.X", "10".
	Generation string
}

// LLMEnrichment holds the results of a post-scan LLM analysis pass.
type LLMEnrichment struct {
	// Summary is a human-readable synopsis of the findings.
	Summary string
	// NucleiTemplates is a list of suggested Nuclei template IDs.
	NucleiTemplates []string
	// CVEs is a list of CVE identifiers relevant to the service.
	CVEs []string
	// ExploitHints is a list of actionable exploitation suggestions.
	ExploitHints []string
	// Confidence is the model's self-reported confidence in [0.0, 1.0].
	Confidence float64
}

// ScanResult is the aggregate result of a complete Portex scan session.
type ScanResult struct {
	// ScanID is a unique identifier for this scan run.
	ScanID string
	// SessionID is the optional Phantom EASM session correlation ID.
	SessionID string
	// StartTime is when the scan began.
	StartTime time.Time
	// EndTime is when the scan completed.
	EndTime time.Time
	// Targets is the list of hosts/CIDRs that were scanned.
	Targets []string
	// TotalPorts is the total number of port probes dispatched.
	TotalPorts int
	// OpenPorts is the count of ports found in StateOpen.
	OpenPorts int
	// Ports holds the per-port result details.
	Ports []PortResult
	// OSMatches maps target IP addresses to their OS detection results.
	OSMatches map[string][]OSMatch
	// Stats holds aggregate performance metrics for the scan.
	Stats ScanStats
}

// ScanStats holds performance and coverage metrics collected during a scan.
type ScanStats struct {
	// ProbesSent is the total number of probe packets transmitted.
	ProbesSent int64
	// ProbesReceived is the number of probe responses received.
	ProbesReceived int64
	// PacketLoss is the fraction of probes with no response in [0.0, 1.0].
	PacketLoss float64
	// AvgRTT is the mean round-trip time across all successful probes.
	AvgRTT time.Duration
	// MaxRTT is the highest observed round-trip time.
	MaxRTT time.Duration
	// ScanRate is the measured throughput in probes per second.
	ScanRate float64
}
