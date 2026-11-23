// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

package metrics

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestPrometheusMetricsScrape(t *testing.T) {
	pm := InitPrometheus("127.0.0.1:19191", true)
	if pm == nil {
		t.Fatal("InitPrometheus returned nil")
	}

	pm.RecordPasswordRotation(true, 1500*time.Millisecond)
	pm.RecordPasswordRotation(false, 250*time.Millisecond)
	pm.SetSecureTokenStatus(true)

	var resp *http.Response
	var err error
	for i := 0; i < 20; i++ {
		resp, err = http.Get("http://127.0.0.1:19191/metrics")
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("could not scrape /metrics: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed reading /metrics body: %v", err)
	}
	text := string(body)
	for _, want := range []string{
		"laps_password_rotations_total 1",
		"laps_password_rotation_errors_total 1",
		"laps_secure_token_status 1",
		"laps_rotation_duration_seconds_count 2",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("/metrics output missing %q", want)
		}
	}
}
