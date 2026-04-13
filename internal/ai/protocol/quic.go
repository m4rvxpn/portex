package protocol

import "context"

// QUICProber sends a QUIC Initial packet to probe port 443/8443.
// Returns true if a QUIC response is received.
//
// NOTE: This is a stub implementation. Full QUIC Initial packet construction
// (RFC 9000) and response parsing will be implemented in Phase 7.
type QUICProber struct{}

// NewQUICProber creates a new QUICProber.
func NewQUICProber() *QUICProber { return &QUICProber{} }

// Probe sends a minimal QUIC Initial packet to target:port.
// Stub: always returns false (no QUIC response) without network I/O.
// TODO(phase7): Construct a real QUIC Initial packet and dial the target.
func (q *QUICProber) Probe(_ context.Context, _ string, _ int) (bool, error) {
	return false, nil
}
