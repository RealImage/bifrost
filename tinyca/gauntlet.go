package tinyca

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/RealImage/bifrost"
	"github.com/VictoriaMetrics/metrics"
	"github.com/google/uuid"
)

type gauntletHolder struct {
	Gauntlet

	// metrics
	denied   *metrics.Counter
	aborted  *metrics.Counter
	duration *metrics.Histogram
}

func newGauntletHolder(g Gauntlet, ns uuid.UUID) *gauntletHolder {
	if g == nil {
		return &gauntletHolder{}
	}

	denied := bfMetricName("gauntlet_denied_total", ns)
	aborted := bfMetricName("gauntlet_aborted_total", ns)
	duration := bfMetricName("gauntlet_duration_seconds", ns)

	return &gauntletHolder{
		Gauntlet: g,

		denied:   bifrost.StatsForNerds.GetOrCreateCounter(denied),
		aborted:  bifrost.StatsForNerds.GetOrCreateCounter(aborted),
		duration: bifrost.StatsForNerds.GetOrCreateHistogram(duration),
	}
}

func (gh *gauntletHolder) throw(csr *bifrost.CertificateRequest) (*x509.Certificate, error) {
	if gh.Gauntlet == nil {
		return TLSClientCertTemplate(), nil
	}

	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)

	timer := time.NewTimer(GauntletTimeout)
	go func() {
		<-timer.C
		cancel(fmt.Errorf("%w, gauntlet timed out", bifrost.ErrRequestAborted))
	}()

	result := make(chan *x509.Certificate, 1)
	go func() {
		defer close(result)

		start := time.Now()
		template, err := gh.Gauntlet(ctx, csr)
		gh.duration.UpdateDuration(start)

		if err != nil {
			cancel(fmt.Errorf("%w, %s", bifrost.ErrRequestDenied, err))
		} else {
			if template == nil {
				template = TLSClientCertTemplate()
			}
			result <- template
		}
	}()

	select {
	case <-ctx.Done():
		err := context.Cause(ctx)
		if errors.Is(err, bifrost.ErrRequestAborted) {
			gh.aborted.Inc()
		}
		if errors.Is(err, bifrost.ErrRequestDenied) {
			gh.denied.Inc()
		}
		return nil, err
	case tmpl := <-result:
		return tmpl, nil
	}
}
