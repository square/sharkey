package telemetry

import (
	"github.com/armon/go-metrics"
	"github.com/armon/go-metrics/datadog"
)

const (
	// Prepended to metrics
	Service = "sharkey"

	// metrics related to github, should be used with other tags
	GitHub = "github"

	// metrics related to background sync jobs, should be used with a broader tag such as "github"
	SyncJob = "sync_job"

	// metrics related to fetching, should be used with a broader tag such as "github"
	Fetch = "fetch"

	// tags that describe the metric being fetched, should be used with other tags
	Calls   = "calls"
	Latency = "latency"
	Count   = "count"
	Success = "success"
)

type Telemetry struct {
	Metrics *metrics.Metrics
}

func CreateTelemetry(addr string) (*Telemetry, error) {
	var sink metrics.MetricSink
	if addr == "" {
		sink = &metrics.BlackholeSink{}
	} else {
		var err error
		sink, err = datadog.NewDogStatsdSink(addr, "")
		if err != nil {
			return nil, err
		}
	}

	metricsImpl, err := metrics.New(metrics.DefaultConfig(Service), sink)
	metricsImpl.EnableHostname = false
	if err != nil {
		return nil, err
	}
	return &Telemetry{
		Metrics: metricsImpl,
	}, nil
}
