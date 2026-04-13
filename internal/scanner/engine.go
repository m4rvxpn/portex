package scanner

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/m4rvxpn/portex/internal/config"
)

// DispatchFunc is the function signature for dispatching a single probe.
// It is injected into the Engine to avoid an import cycle between the
// scanner and packet packages.
type DispatchFunc func(ctx context.Context, p Probe) (PortResult, error)

// Engine is a single-use goroutine pool for dispatching port probes.
// Start, Submit/Drain, and Results follow a strict lifecycle:
//  1. NewEngine → 2. Start → 3. Submit × N → 4. Drain → 5. consume Results
//
// Do not call Start or Submit after Drain has been called. Construct a new
// Engine for each scan invocation.
type Engine struct {
	workers  int
	probeQ   chan Probe      // buffered input queue
	resultQ  chan PortResult // buffered output queue
	limiter  *RateLimiter
	cfg      *config.Config
	dispatch DispatchFunc
	wg       sync.WaitGroup

	// stats (atomic)
	probesSent     atomic.Int64
	probesReceived atomic.Int64
}

// NewEngine creates a new Engine.
// workers: number of goroutines in the pool (from cfg.Goroutines).
// dispatchFn: the function that actually sends a probe and returns a result.
func NewEngine(cfg *config.Config, dispatchFn DispatchFunc) *Engine {
	workers := cfg.Goroutines
	if workers <= 0 {
		workers = 1000
	}

	timing := GetTiming(int(cfg.Timing))
	pps := timing.MaxParallel
	if pps <= 0 {
		pps = 1000
	}

	return &Engine{
		workers:  workers,
		probeQ:   make(chan Probe, workers*2),
		resultQ:  make(chan PortResult, workers*2),
		limiter:  NewRateLimiter(pps),
		cfg:      cfg,
		dispatch: dispatchFn,
	}
}

// Start launches the worker goroutine pool. Non-blocking.
func (e *Engine) Start(ctx context.Context) {
	for i := 0; i < e.workers; i++ {
		e.wg.Add(1)
		go e.workerLoop(ctx)
	}
}

// Submit enqueues a probe for dispatch. Returns ctx.Err() if the context is
// cancelled while waiting for queue space.
func (e *Engine) Submit(ctx context.Context, p Probe) error {
	select {
	case e.probeQ <- p:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Results returns the channel of completed port results.
func (e *Engine) Results() <-chan PortResult {
	return e.resultQ
}

// Drain waits for all submitted probes to be processed, then closes Results().
func (e *Engine) Drain() {
	close(e.probeQ)
	e.wg.Wait()
	close(e.resultQ)
}

// Stats returns current scan statistics.
func (e *Engine) Stats() ScanStats {
	sent := e.probesSent.Load()
	recv := e.probesReceived.Load()
	var loss float64
	if sent > 0 {
		loss = float64(sent-recv) / float64(sent)
	}
	return ScanStats{
		ProbesSent:     sent,
		ProbesReceived: recv,
		PacketLoss:     loss,
	}
}

// workerLoop is the hot loop for each goroutine.
func (e *Engine) workerLoop(ctx context.Context) {
	defer e.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case p, ok := <-e.probeQ:
			if !ok {
				return
			}
			result, _ := e.runProbe(ctx, p)
			select {
			case e.resultQ <- result:
			case <-ctx.Done():
				return
			}
		}
	}
}

// runProbe applies rate limiting, calls dispatch, and records stats.
func (e *Engine) runProbe(ctx context.Context, p Probe) (PortResult, error) {
	// Apply timing deadline via context.
	probeCtx := ctx
	var cancel context.CancelFunc

	if !p.Deadline.IsZero() && time.Until(p.Deadline) > 0 {
		probeCtx, cancel = context.WithDeadline(ctx, p.Deadline)
		defer cancel()
	} else {
		timing := GetTiming(int(e.cfg.Timing))
		probeCtx, cancel = context.WithTimeout(ctx, timing.MaxRTT)
		defer cancel()
	}

	// Wait for rate limiter token.
	if err := e.limiter.Wait(probeCtx); err != nil {
		return PortResult{
			Target:    p.Target,
			Port:      p.Port,
			Protocol:  p.Protocol,
			State:     StateUnknown,
			Reason:    "rate-limit-cancelled",
			Timestamp: time.Now(),
		}, fmt.Errorf("rate limiter: %w", err)
	}

	e.probesSent.Add(1)

	result, err := e.dispatch(probeCtx, p)

	if err == nil {
		e.probesReceived.Add(1)
		if result.RTT > 0 {
			e.limiter.AdaptFromRTT(result.RTT)
		}
	}

	return result, err
}
