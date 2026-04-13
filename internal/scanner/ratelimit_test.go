package scanner

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRateLimiter_RespectsPPS(t *testing.T) {
	limiter := NewRateLimiter(100) // 100 PPS → 10ms per token
	ctx := context.Background()

	start := time.Now()
	for i := 0; i < 10; i++ {
		err := limiter.Wait(ctx)
		require.NoError(t, err)
	}
	elapsed := time.Since(start)

	// 10 tokens at 100 PPS = 100ms minimum; allow generous tolerance of 80ms
	assert.GreaterOrEqual(t, elapsed, 80*time.Millisecond,
		"10 waits at 100 PPS should take at least 80ms, got %v", elapsed)
}

func TestRateLimiter_ContextCancellation(t *testing.T) {
	// 1 PPS = 1000ms per token; cancel almost immediately
	limiter := NewRateLimiter(1)
	// Drain the initial token so the next Wait will block
	ctx := context.Background()
	err := limiter.Wait(ctx)
	require.NoError(t, err)

	cancelCtx, cancel := context.WithCancel(context.Background())

	// Cancel after a short delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	err = limiter.Wait(cancelCtx)
	assert.ErrorIs(t, err, context.Canceled, "Wait should return ctx.Err() on cancellation")
}

func TestRateLimiter_ConcurrentSafe(t *testing.T) {
	limiter := NewRateLimiter(10000) // high PPS so goroutines finish quickly
	ctx := context.Background()

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_ = limiter.Wait(ctx)
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All goroutines completed without panic or race
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for concurrent Wait calls to complete")
	}
}
