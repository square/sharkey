package telemetry

import (
	"net/http"
	"strings"
	"time"

	"github.com/felixge/httpsnoop"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

type MetricsMiddleware struct {
	telemetry *Telemetry
}

func NewMetricsMiddleware(t *Telemetry) *MetricsMiddleware {
	return &MetricsMiddleware{t}
}

func (m *MetricsMiddleware) InstrumentHTTPEndpointStats(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		logger, w := makeMetricsResponseLogger(w)

		route := mux.CurrentRoute(r)
		path, err := route.GetPathTemplate()
		if err != nil {
			logrus.Warn("unable to retrieve path from route for metrics")
		}

		endpoint := m.parseRoute(path)

		h.ServeHTTP(w, r)

		if endpoint != "" {
			m.telemetry.Metrics.IncrCounter([]string{endpoint, Count}, 1)
			m.telemetry.Metrics.SetGauge([]string{endpoint, Latency}, float32(time.Since(start).Milliseconds()))
			if logger.Status() >= 500 {
				m.telemetry.Metrics.IncrCounter([]string{endpoint, "500"}, 1)
			} else if logger.Status() >= 400 {
				m.telemetry.Metrics.IncrCounter([]string{endpoint, "400"}, 1)
			} else if logger.Status() >= 200 && logger.status < 300 {
				m.telemetry.Metrics.IncrCounter([]string{endpoint, "200"}, 1)
			}
		}
	})
}

func (m *MetricsMiddleware) parseRoute(routeName string) string {
	switch routeName {
	case "/enroll/{hostname}":
		return "enroll_host"
	default:
		return strings.ReplaceAll(strings.Trim(routeName, "/"), "/", "_")
	}
}

// metricsResponseLogger hooks onto an http ResponseWriter and tracks the http response code of that ResponseWriter
// When the ResponseWriter writes the response code into the http header, we hook into that function and record
// the response code
type metricsResponseLogger struct {
	w      http.ResponseWriter
	status int
}

func (l *metricsResponseLogger) WriteHeader(code int) {
	l.status = code
}

func (l *metricsResponseLogger) Status() int {
	return l.status
}

func makeMetricsResponseLogger(w http.ResponseWriter) (*metricsResponseLogger, http.ResponseWriter) {
	logger := &metricsResponseLogger{w: w, status: http.StatusOK}
	return logger, httpsnoop.Wrap(w, httpsnoop.Hooks{
		WriteHeader: func(httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
			return logger.WriteHeader
		},
	})
}
