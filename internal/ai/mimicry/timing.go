// Package mimicry implements traffic mimicry: timing profiles, OS TCP stack
// fingerprints, and decoy flood generation.
package mimicry

import (
	"math/rand"
	"time"
)

// TimingProfile defines inter-packet timing parameters for a benign traffic pattern.
type TimingProfile struct {
	Name   string
	MinGap time.Duration
	MaxGap time.Duration
	// Jitter factor 0.0-1.0: fraction of gap that is randomized.
	Jitter float64
}

var (
	// BrowserProfile mimics a human browsing session.
	BrowserProfile = TimingProfile{
		Name:   "browser",
		MinGap: 50 * time.Millisecond,
		MaxGap: 500 * time.Millisecond,
		Jitter: 0.4,
	}
	// CrawlerProfile mimics a web crawler.
	CrawlerProfile = TimingProfile{
		Name:   "crawler",
		MinGap: 100 * time.Millisecond,
		MaxGap: 2 * time.Second,
		Jitter: 0.2,
	}
	// NmapProfile mimics nmap T3 timing (no artificial delay).
	NmapProfile = TimingProfile{
		Name:   "nmap_t3",
		MinGap: 0,
		MaxGap: 0,
		Jitter: 0,
	}
)

// NextDelay computes the next inter-packet delay for the given profile.
// The base delay is drawn uniformly from [MinGap, MaxGap], then a jitter
// of up to ±(Jitter * base) is added.
func NextDelay(p TimingProfile) time.Duration {
	if p.MaxGap <= p.MinGap {
		return p.MinGap
	}

	span := p.MaxGap - p.MinGap
	base := p.MinGap + time.Duration(rand.Int63n(int64(span)+1)) //nolint:gosec

	if p.Jitter <= 0 {
		return base
	}

	// Add symmetric jitter: ±(jitter * base)
	maxJitter := float64(base) * p.Jitter
	jitter := time.Duration((rand.Float64()*2 - 1) * maxJitter) //nolint:gosec

	d := base + jitter
	if d < 0 {
		d = 0
	}
	return d
}
