package metrics

import (
	"github.com/armon/go-metrics/datadog"
	"github.com/sirupsen/logrus"
)

type Metrics struct {
	sink *datadog.DogStatsdSink
}

func CreateMetrics(addr string) *Metrics {
	sink, err := datadog.NewDogStatsdSink(addr, "")
	if err != nil {
		logrus.Error(err)
	}
	return &Metrics{
		sink: sink,
	}
}
