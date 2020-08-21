package telemetry

import (
	"github.com/armon/go-metrics/datadog"
)

const (
	GitHubSyncJobLatency = "github_sync_job_latency"
	GitHubFetches        = "github_fetches"
	GitHubFetchLatency   = "github_fetch_latency"
	GitHubFetchedUsers   = "github_fetched_users"
)

type MetricSink interface {
	// labels are a list of metrics that should be updated with the value
	// for 1:1 label to value metric, use an array with a single label
	IncrCounter(labels []string, value float32)
	SetGauge(labels []string, value float32)
}

type Telemetry struct {
	Sink MetricSink
}

func CreateTelemetry(addr string) (*Telemetry, error) {
	sink, err := datadog.NewDogStatsdSink(addr, "")
	if err != nil {
		return nil, err
	}
	return &Telemetry{
		Sink: sink,
	}, nil
}
