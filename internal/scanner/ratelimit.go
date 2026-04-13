// Package scanner contains core scanning types, engine primitives, and result models.
package scanner

import (
	"context"
	"sync"
	"time"
)

const (
	// rttSpikeThreshold is the multiplier above the running average RTT that
	// triggers an automatic rate reduction.
	rttSpikeThreshold = 1.5
	// rttAdaptFactor is the fraction by which the rate is reduced on an RTT spike.
	rttAdaptFactor = 0.75
	// minPPS is the floor rate enforced by AdaptFromRTT to prevent stalling.
	minPPS = 10
)

// RateLimiter is an adaptive token-bucket rate limiter. It allows up to pps
// probes per second and can automatically reduce throughput when elevated RTT
// values indicate network congestion.
type RateLimiter struct {
	mu sync.Mutex

	pps      int           // current target rate (probes per second)
	interval time.Duration // time between tokens  = 1s / pps

	tokens   float64   // current token balance
	lastFill time.Time // last token-fill timestamp

	avgRTT time.Duration // exponentially weighted moving average RTT
}

// NewRateLimiter creates a RateLimiter that allows up to pps probes per second.
// If pps is <= 0 it is silently clamped to 1.
func NewRateLimiter(pps int) *RateLimiter {
	if pps <= 0 {
		pps = 1
	}
	return &RateLimiter{
		pps:      pps,
		interval: time.Second / time.Duration(pps),
		tokens:   1,
		lastFill: time.Now(),
	}
}

// Wait blocks until a token is available or ctx is cancelled.
// It returns ctx.Err() if the context is cancelled before a token arrives.
func (r *RateLimiter) Wait(ctx context.Context) error {
	for {
		r.mu.Lock()
		now := time.Now()
		// Refill tokens based on elapsed time since last fill.
		elapsed := now.Sub(r.lastFill)
		r.lastFill = now
		r.tokens += elapsed.Seconds() * float64(r.pps)
		// Cap bucket at burst size of 1 second worth of tokens.
		maxTokens := float64(r.pps)
		if r.tokens > maxTokens {
			r.tokens = maxTokens
		}

		if r.tokens >= 1 {
			r.tokens--
			r.mu.Unlock()
			return nil
		}

		// Calculate how long until the next token arrives.
		wait := time.Duration((1-r.tokens) / float64(r.pps) * float64(time.Second))
		r.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
			// Loop back to try consuming a token.
		}
	}
}

// SetRate dynamically adjusts the target rate to pps probes per second.
// If pps is <= 0 it is silently clamped to 1.
func (r *RateLimiter) SetRate(pps int) {
	if pps <= 0 {
		pps = 1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pps = pps
	r.interval = time.Second / time.Duration(pps)
}

// AdaptFromRTT updates the exponentially weighted moving average RTT and
// reduces the probe rate when the observed RTT exceeds 1.5× the running
// average, signalling network congestion. The rate will never fall below
// minPPS (10 pps).
func (r *RateLimiter) AdaptFromRTT(rtt time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.avgRTT == 0 {
		r.avgRTT = rtt
		return
	}

	// Exponentially weighted moving average with α = 0.125 (same as TCP SRTT).
	const alpha = 0.125
	r.avgRTT = time.Duration(float64(r.avgRTT)*(1-alpha) + float64(rtt)*alpha)

	// Reduce rate if this sample exceeds the spike threshold.
	if float64(rtt) > float64(r.avgRTT)*rttSpikeThreshold {
		newPPS := int(float64(r.pps) * rttAdaptFactor)
		if newPPS < minPPS {
			newPPS = minPPS
		}
		r.pps = newPPS
		r.interval = time.Second / time.Duration(r.pps)
	}
}
