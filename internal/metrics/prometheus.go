// internal/metrics/prometheus.go
package metrics

import (
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type PrometheusMetrics struct {
	passwordRotations      prometheus.Counter
	passwordRotationErrors prometheus.Counter
	rotationDuration       prometheus.Histogram
	secureTokenStatus      prometheus.Gauge
}

var (
	metricsInstance *PrometheusMetrics
	metricsOnce     sync.Once
)

func InitPrometheus(port string, enabled bool) *PrometheusMetrics {
	metricsOnce.Do(func() {
		if !enabled {
			return
		}

		metricsInstance = &PrometheusMetrics{
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

		// Register metrics
		prometheus.MustRegister(metricsInstance.passwordRotations)
		prometheus.MustRegister(metricsInstance.passwordRotationErrors)
		prometheus.MustRegister(metricsInstance.rotationDuration)
		prometheus.MustRegister(metricsInstance.secureTokenStatus)

		// Start HTTP server for metrics endpoint
		http.Handle("/metrics", promhttp.Handler())
		go func() {
			log.Printf("[INFO] Prometheus metrics server starting on %s", port)
			if err := http.ListenAndServe(port, nil); err != nil {
				log.Printf("[ERROR] Prometheus metrics server failed: %v", err)
			}
		}()
	})

	return metricsInstance
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

// GetMetrics returns the singleton instance
func GetMetrics() *PrometheusMetrics {
	return metricsInstance
}
