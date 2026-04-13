package mutator

// SrcRouteMutator adds an IP Loose Source Routing (LSRR) option to the IP header.
//
// NOTE: Full LSRR implementation requires adjusting the IHL field, shifting
// the existing payload, and recalculating the IP checksum. This is a stub
// that returns the original frame unchanged.
// TODO(phase7): Implement RFC 791 LSRR option insertion.
type SrcRouteMutator struct {
	HopIPs []string
}

// NewSrcRouteMutator creates a SrcRouteMutator with the given intermediate hop IPs.
func NewSrcRouteMutator(hops []string) *SrcRouteMutator {
	return &SrcRouteMutator{HopIPs: hops}
}

// Mutate is a stub: returns the original frame unchanged.
// TODO(phase7): Insert LSRR IP option, update IHL, recalculate checksum.
func (m *SrcRouteMutator) Mutate(frame []byte) ([]byte, error) {
	out := make([]byte, len(frame))
	copy(out, frame)
	return out, nil
}

// Name returns the mutator identifier.
func (m *SrcRouteMutator) Name() string { return "srcroute" }
