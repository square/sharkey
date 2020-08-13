package telemetry

import (
	"github.com/armon/go-metrics/datadog"
)

type MetricSink interface {
	IncrCounter([]string, float32)
	SetGauge([]string, float32)
}

type Metrics struct {
	Sink MetricSink
}

func CreateMetrics(addr string) (*Metrics, error) {
	sink, err := datadog.NewDogStatsdSink(addr, "")
	if err != nil {
		return nil, err
	}
	return &Metrics{
		Sink: sink,
	}, nil
}
