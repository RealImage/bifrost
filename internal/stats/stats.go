package stats

import (
	"net/http"

	"github.com/VictoriaMetrics/metrics"
)

// ForNerds captures metrics from various bifrost processes
var ForNerds = metrics.NewSet()

// MetricsHandler is a HTTP handler that returns metrics from the ForNerds MetricsSet
func MetricsHandler(w http.ResponseWriter, _ *http.Request) {
	ForNerds.WritePrometheus(w)
}
