package stats

import (
	"log"
	"net/http"
	"time"

	"github.com/VictoriaMetrics/metrics"
)

const defaultPushInterval = time.Minute

// ForNerds captures metrics from various bifrost processes
var ForNerds = metrics.NewSet()

// MaybePushMetrics pushes metrics to url if url is not empty
func MaybePushMetrics(url string, interval time.Duration) {
	if url == "" {
		return
	}
	if interval == 0 {
		interval = defaultPushInterval
	}

	log.Printf("pushing metrics to %s every %.2fs\n", url, interval.Seconds())
	if err := ForNerds.InitPush(url, interval, ""); err != nil {
		log.Fatalf("error setting up metrics push: %s\n", err)
	}
}

// MetricsHandler is a HTTP handler that returns metrics from the ForNerds MetricsSet
func MetricsHandler(w http.ResponseWriter, _ *http.Request) {
	ForNerds.WritePrometheus(w)
}
