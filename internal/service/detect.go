package service

import (
	"context"
	"time"
)

// Detector orchestrates service detection on an open port.
type Detector struct {
	db      *ProbeDB
	grabber *BannerGrabber
}

// NewDetector creates a new Detector using the given probe database.
// Uses a default banner grab timeout of 5 seconds.
func NewDetector(db *ProbeDB) *Detector {
	return &Detector{
		db:      db,
		grabber: NewBannerGrabber(5 * time.Second),
	}
}

// Detect runs service detection probes against target:port.
// It tries probes in rarity order, stopping on first confident match.
func (d *Detector) Detect(ctx context.Context, target string, port int, proto string) (*Match, error) {
	probes := d.db.FindProbesForPort(port, proto)

	// First, try a null probe (empty payload) to grab the initial banner
	banner, err := d.grabber.Grab(ctx, target, port, proto)
	if err == nil && len(banner) > 0 {
		if m := d.db.MatchBanner(banner, probes); m != nil {
			m.Banner = string(banner)
			return m, nil
		}
	}

	// Try each probe in order
	for _, probe := range probes {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		if len(probe.Payload) == 0 {
			continue // already tried null probe
		}

		response, err := d.grabber.GrabWithProbe(ctx, target, port, proto, probe.Payload)
		if err != nil || len(response) == 0 {
			continue
		}

		// Try to match the response
		singleProbeSlice := []ServiceProbe{probe}
		if m := d.db.MatchBanner(response, singleProbeSlice); m != nil {
			m.Banner = string(response)
			m.Probe = probe.Name
			return m, nil
		}
	}

	// If we got a banner but no match, return a minimal match with the raw banner
	if len(banner) > 0 {
		return &Match{
			Banner: string(banner),
			Conf:   1,
		}, nil
	}

	return nil, nil
}
