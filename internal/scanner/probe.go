// Package scanner contains core scanning types, engine primitives, and result models.
package scanner

import "time"

// ScanMode identifies the packet-craft strategy used for a probe.
// This mirrors config.ScanMode but is redefined here as a plain string
// type to avoid a circular import between the scanner and config packages.
type ScanMode = string

const (
	// ScanModeSYN is a half-open TCP SYN scan.
	ScanModeSYN ScanMode = "syn"
	// ScanModeACK probes with TCP ACK packets.
	ScanModeACK ScanMode = "ack"
	// ScanModeFIN sends TCP FIN packets.
	ScanModeFIN ScanMode = "fin"
	// ScanModeXMAS sets FIN, PSH and URG flags.
	ScanModeXMAS ScanMode = "xmas"
	// ScanModeNULL sends TCP packets with no flags.
	ScanModeNULL ScanMode = "null"
	// ScanModeWindow examines TCP window size in ACK responses.
	ScanModeWindow ScanMode = "window"
	// ScanModeMaimon is a FIN/ACK probe.
	ScanModeMaimon ScanMode = "maimon"
	// ScanModeUDP sends UDP probes.
	ScanModeUDP ScanMode = "udp"
	// ScanModeSCTP sends SCTP INIT chunks.
	ScanModeSCTP ScanMode = "sctp"
	// ScanModeIPProto iterates IP protocol numbers.
	ScanModeIPProto ScanMode = "ipproto"
	// ScanModeIdle performs an idle (zombie) scan.
	ScanModeIdle ScanMode = "idle"
	// ScanModeFTP performs an FTP bounce scan.
	ScanModeFTP ScanMode = "ftp"
	// ScanModeConnect uses a full TCP connect() call.
	ScanModeConnect ScanMode = "connect"
	// ScanModeStealth is SYN scan with all AI evasion layers enabled.
	ScanModeStealth ScanMode = "stealth"
)

// Probe is a single unit of work dispatched by the scanner engine.
// The RL agent may adjust SrcPort, TTL, and Payload before transmission.
type Probe struct {
	// Target is the destination IP address or hostname.
	Target string
	// Port is the destination port number.
	Port int
	// Protocol is one of "tcp", "udp", or "sctp".
	Protocol string
	// ScanMode is the probe technique to use (matches config.ScanMode values).
	ScanMode ScanMode
	// Attempt is the zero-based retry count for this probe.
	Attempt int
	// SrcPort is the source port to use; 0 means auto-assign.
	SrcPort int
	// TTL overrides the IP time-to-live field; 0 means OS default.
	TTL uint8
	// Payload is an optional custom application-layer payload.
	Payload []byte
	// Deadline is the absolute time after which the probe is abandoned.
	Deadline time.Time
}
