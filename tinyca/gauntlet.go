package tinyca

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"plugin"
	"strings"
	"sync"
	"time"

	"github.com/RealImage/bifrost"
	"github.com/VictoriaMetrics/metrics"
	"github.com/google/uuid"
)

// GauntletTimeout is the maximum time the CA Gauntlet function is allowed to run.
const GauntletTimeout = 100 * time.Millisecond

// Gauntlet is the signature for a function that validates a certificate request.
// If the second return value is non-nil, then the certificate request is denied.
// If the first return value is nil, the default template TLSClientCertTemplate will be used.
// If the function exceeds GauntletTimeout, ctx will be cancelled and the
// request will be denied with an error.
// The template will be used to issue a client certificate.
// Consult the x509 package for the full list of fields that can be set.
// tinyca will overwrite the following template fields:
//   - NotBefore
//   - NotAfter
//   - SignatureAlgorithm
//   - Issuer
//   - Subject.Organization
//   - Subject.CommonName
//
// If SerialNumber is nil, a random value will be generated.
type Gauntlet func(ctx context.Context, csr *bifrost.CertificateRequest) (tmpl *x509.Certificate, err error)

// LoadGaugelet loads the a Gauntlet function from the Go plugin
// at the given path.
// The plugin must export a symbol named "Gauntlet" of type *Gauntlet.
// If the path is empty, LoadGauntlet returns nil.
// If the path does not end with ".so", it will be appended.
func LoadGauntlet(pluginPath string) (Gauntlet, error) {
	if pluginPath == "" {
		return nil, nil
	}

	if !strings.HasSuffix(pluginPath, ".so") {
		pluginPath += ".so"
	}
	plug, err := plugin.Open(pluginPath)
	if err != nil {
		return nil, fmt.Errorf("error opening plugin %s: %w", pluginPath, err)
	}

	sym, err := plug.Lookup("Gauntlet")
	if err != nil {
		return nil, fmt.Errorf("error looking up Gauntlet symbol in plugin %s: %w", pluginPath, err)
	}

	gauntlet, ok := sym.(*Gauntlet)
	if !ok {
		return nil, fmt.Errorf("expected symbol *Gauntlet but got %T instead", sym)
	}
	if gauntlet == nil || *gauntlet == nil {
		return nil, errors.New("Gauntlet symbol is nil")
	}

	return *gauntlet, nil
}

type gauntletThrower struct {
	Gauntlet

	wg *sync.WaitGroup

	// metrics
	denied   *metrics.Counter
	aborted  *metrics.Counter
	duration *metrics.Histogram
}

func newGauntletThrower(g Gauntlet, ns uuid.UUID) *gauntletThrower {
	if g == nil {
		return &gauntletThrower{}
	}

	denied := bfMetricName("gauntlet_denied_total", ns)
	aborted := bfMetricName("gauntlet_aborted_total", ns)
	duration := bfMetricName("gauntlet_duration_seconds", ns)

	return &gauntletThrower{
		Gauntlet: g,

		wg: new(sync.WaitGroup),

		denied:   bifrost.StatsForNerds.GetOrCreateCounter(denied),
		aborted:  bifrost.StatsForNerds.GetOrCreateCounter(aborted),
		duration: bifrost.StatsForNerds.GetOrCreateHistogram(duration),
	}
}

func (gh *gauntletThrower) throw(csr *bifrost.CertificateRequest) (*x509.Certificate, error) {
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
	gh.wg.Add(1)
	go func() {
		defer gh.wg.Done()
		defer close(result)
		defer func() {
			if r := recover(); r != nil {
				bifrost.Logger().ErrorContext(ctx, "gauntlet panic", "recovered", r)
				cancel(fmt.Errorf("%w, gauntlet panic('%v')", bifrost.ErrRequestAborted, r))
			}
		}()

		start := time.Now()
		template, err := gh.Gauntlet(ctx, csr)
		gh.duration.UpdateDuration(start)
		bifrost.Logger().DebugContext(ctx, "threw gauntlet", "duration", time.Since(start))

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

func (gh *gauntletThrower) Close() error {
	if gh.wg != nil {
		gh.wg.Wait()
	}

	return nil
}
