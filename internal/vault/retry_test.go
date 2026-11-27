// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

package vault

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

var errBoom = errors.New("boom")

func zeroBackoff(t *testing.T) {
	t.Helper()
	saved := retryBackoff
	retryBackoff = func(int) time.Duration { return 0 }
	t.Cleanup(func() { retryBackoff = saved })
}

func TestWithRetryReportsTheAttemptsRunWhenTheContextEndsInACall(t *testing.T) {
	zeroBackoff(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	_, err := withRetry(ctx, "probe", func(context.Context) (int, error) {
		calls++
		if calls == 2 {
			cancel()
		}
		return 0, errors.New("boom")
	})
	if err == nil {
		t.Fatal("withRetry returned nil, want an error")
	}
	if calls != 2 {
		t.Fatalf("withRetry ran %d attempts, want 2", calls)
	}
	if !strings.Contains(err.Error(), "after 2 attempts") {
		t.Fatalf("err = %q, want \"after 2 attempts\"", err)
	}
	if !strings.HasSuffix(err.Error(), "boom") {
		t.Fatalf("err = %q, want the last call error at the end", err)
	}
}

func TestWithRetryReportsTheAttemptsRunWhenTheContextEndsInTheBackoff(t *testing.T) {
	saved := retryBackoff
	retryBackoff = func(int) time.Duration { return time.Hour }
	t.Cleanup(func() { retryBackoff = saved })
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	calls := 0
	start := time.Now()
	_, err := withRetry(ctx, "probe", func(context.Context) (int, error) {
		calls++
		return 0, errBoom
	})
	if time.Since(start) > 5*time.Second {
		t.Fatalf("withRetry waited %s, want a return as soon as the context ended", time.Since(start))
	}
	if err == nil {
		t.Fatal("withRetry returned nil, want an error")
	}
	if calls != 1 {
		t.Fatalf("withRetry ran %d attempts, want 1", calls)
	}
	if !strings.Contains(err.Error(), "after 1 attempts") {
		t.Fatalf("err = %q, want \"after 1 attempts\"", err)
	}
	if !strings.Contains(err.Error(), "the run budget ended during the pause (context deadline exceeded)") {
		t.Fatalf("err = %q, want the budget end and the context error in the text", err)
	}
	if !strings.HasSuffix(err.Error(), "boom") || !errors.Is(err, errBoom) {
		t.Fatalf("err = %q, want the last call error wrapped at the end", err)
	}
}
