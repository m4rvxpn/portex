// Package scanner contains core scanning types, engine primitives, and result models.
package scanner

import "time"

// TimingConfig holds the concrete timing parameters derived from a profile.
type TimingConfig struct {
	// MinRTT is the minimum round-trip time floor used for adaptive timing.
	MinRTT time.Duration
	// MaxRTT is the maximum time to wait for a probe response.
	MaxRTT time.Duration
	// InitialRTT is the assumed RTT before any measurements are available.
	InitialRTT time.Duration
	// MaxRetries is the maximum number of retransmissions per probe.
	MaxRetries int
	// ScanDelay is the minimum inter-probe delay (0 = no enforced delay).
	ScanDelay time.Duration
	// MaxParallel is the maximum number of concurrent outstanding probes.
	MaxParallel int
	// HostTimeout is the maximum total time allowed per target host.
	HostTimeout time.Duration
}

// TimingProfiles maps nmap-style timing template indices (0–5) to their
// corresponding TimingConfig values.
var TimingProfiles = map[int]TimingConfig{
	// T0 – paranoid: single probe at a time, extremely long delays.
	0: {
		MinRTT:      100 * time.Millisecond,
		MaxRTT:      5 * time.Minute,
		InitialRTT:  5 * time.Second,
		MaxRetries:  10,
		ScanDelay:   5 * time.Minute,
		MaxParallel: 1,
		HostTimeout: 5 * time.Minute,
	},
	// T1 – sneaky: very slow, suitable for IDS evasion.
	1: {
		MinRTT:      100 * time.Millisecond,
		MaxRTT:      15 * time.Second,
		InitialRTT:  2 * time.Second,
		MaxRetries:  10,
		ScanDelay:   15 * time.Second,
		MaxParallel: 10,
		HostTimeout: 15 * time.Second,
	},
	// T2 – polite: reduces network load.
	2: {
		MinRTT:      100 * time.Millisecond,
		MaxRTT:      10 * time.Second,
		InitialRTT:  1 * time.Second,
		MaxRetries:  6,
		ScanDelay:   400 * time.Millisecond,
		MaxParallel: 100,
		HostTimeout: 10 * time.Second,
	},
	// T3 – normal: balanced default profile.
	3: {
		MinRTT:      100 * time.Millisecond,
		MaxRTT:      10 * time.Second,
		InitialRTT:  1 * time.Second,
		MaxRetries:  6,
		ScanDelay:   0,
		MaxParallel: 1000,
		HostTimeout: 10 * time.Second,
	},
	// T4 – aggressive: faster, assumes a reliable network.
	4: {
		MinRTT:      10 * time.Millisecond,
		MaxRTT:      1250 * time.Millisecond,
		InitialRTT:  500 * time.Millisecond,
		MaxRetries:  6,
		ScanDelay:   0,
		MaxParallel: 5000,
		HostTimeout: 1250 * time.Millisecond,
	},
	// T5 – insane: maximum speed, sacrifices accuracy.
	5: {
		MinRTT:      5 * time.Millisecond,
		MaxRTT:      300 * time.Millisecond,
		InitialRTT:  250 * time.Millisecond,
		MaxRetries:  2,
		ScanDelay:   0,
		MaxParallel: 10000,
		HostTimeout: 300 * time.Millisecond,
	},
}

// GetTiming returns the TimingConfig for the given profile index.
// If the profile index is out of range [0, 5] it falls back to T3 (normal).
func GetTiming(profile int) TimingConfig {
	if tc, ok := TimingProfiles[profile]; ok {
		return tc
	}
	return TimingProfiles[3]
}
