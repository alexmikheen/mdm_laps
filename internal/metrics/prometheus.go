// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

package metrics

import (
	"context"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type PrometheusMetrics struct {
	passwordRotations      prometheus.Counter
	passwordRotationErrors prometheus.Counter
	rotationDuration       prometheus.Histogram
	secureTokenStatus      prometheus.Gauge
	server                 *http.Server
}

var (
	metricsInstance atomic.Pointer[PrometheusMetrics]
	metricsOnce     sync.Once
)

func InitPrometheus(port string, enabled bool) *PrometheusMetrics {
	if !enabled {
		return nil
	}

	metricsOnce.Do(func() {
		pm := &PrometheusMetrics{
			passwordRotations: prometheus.NewCounter(prometheus.CounterOpts{
				Name: "laps_password_rotations_total",
				Help: "Total number of successful password rotations",
			}),
			passwordRotationErrors: prometheus.NewCounter(prometheus.CounterOpts{
				Name: "laps_password_rotation_errors_total",
				Help: "Total number of password rotation errors",
			}),
			rotationDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
				Name:    "laps_rotation_duration_seconds",
				Help:    "Duration of password rotation process in seconds",
				Buckets: prometheus.DefBuckets,
			}),
			secureTokenStatus: prometheus.NewGauge(prometheus.GaugeOpts{
				Name: "laps_secure_token_status",
				Help: "Secure token status (1=enabled, 0=disabled)",
			}),
		}

		prometheus.MustRegister(pm.passwordRotations)
		prometheus.MustRegister(pm.passwordRotationErrors)
		prometheus.MustRegister(pm.rotationDuration)
		prometheus.MustRegister(pm.secureTokenStatus)

		listenAddr := port
		if strings.HasPrefix(listenAddr, ":") {
			listenAddr = "127.0.0.1" + listenAddr
		}
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		srv := &http.Server{
			Addr:              listenAddr,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		}
		pm.server = srv
		metricsInstance.Store(pm)

		go func() {
			log.Printf("[INFO] Prometheus metrics server starting on %s", listenAddr)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("[ERROR] Prometheus metrics server failed: %v", err)
			}
		}()
	})

	return metricsInstance.Load()
}

func (pm *PrometheusMetrics) Shutdown(ctx context.Context) error {
	if pm == nil || pm.server == nil {
		return nil
	}
	return pm.server.Shutdown(ctx)
}

func (pm *PrometheusMetrics) RecordPasswordRotation(success bool, duration time.Duration) {
	if pm == nil {
		return
	}

	pm.rotationDuration.Observe(duration.Seconds())

	if success {
		pm.passwordRotations.Inc()
	} else {
		pm.passwordRotationErrors.Inc()
	}
}

func (pm *PrometheusMetrics) SetSecureTokenStatus(enabled bool) {
	if pm == nil {
		return
	}

	if enabled {
		pm.secureTokenStatus.Set(1)
	} else {
		pm.secureTokenStatus.Set(0)
	}
}

func GetMetrics() *PrometheusMetrics {
	return metricsInstance.Load()
}
