package stats

import (
	"log"
	"net/http"
	"time"

	"github.com/VictoriaMetrics/metrics"
)

// ForNerds captures metrics from various bifrost processes
var ForNerds = metrics.NewSet()

// MaybePushMetrics pushes metrics to url if url is not empty.
// If interval is zero, a one minute interval is used
func MaybePushMetrics(url string, interval time.Duration) {
	if url == "" {
		return
	}
	if interval == 0 {
		interval = time.Minute
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
