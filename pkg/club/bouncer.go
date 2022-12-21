package club

import (
	"encoding/json"
	"encoding/pem"
	"log"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/RealImage/bifrost/internal/stats"
)

const RequestContextHeader = "x-amzn-request-context"

var requestDuration = stats.ForNerds.NewSummary("bifrost_bouncer_requests_duration_seconds")

// RequestContext contains a subset of fields related to TLS Client Certificates,
// from the larger AWS Lambda Request Context object.
type RequestContext struct {
	Authentication struct {
		ClientCert ClientCert `json:"clientCert"`
	} `json:"authentication"`
}

type ClientCert struct {
	ClientCertPEM []byte   `json:"clientCertPEM"`
	IssuerDN      string   `json:"issuerDN"`
	SerialNumber  string   `json:"serialNumber"`
	SubjectDN     string   `json:"subjectDN"`
	Validity      validity `json:"validity"`
}

type validity struct {
	NotAfter  time.Time `json:"notAfter"`
	NotBefore time.Time `json:"notBefore"`
}

// Bouncer wraps a `httputil.ReverseProxy` and sends a JSON serialized `RequestContext` object
// in the x-amzn-request-context header.
// To create a reverse proxy that mimics AWS API Gateway with mTLS authentication,
// pass an instance of `httputil.NewSingleReverseHostProxy()` to Bouncer.
func Bouncer(rp *httputil.ReverseProxy) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()

		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			panic("request must have tls client certificate")
		}

		peerCert := r.TLS.PeerCertificates[0]
		requestCtx := RequestContext{}
		requestCtx.Authentication.ClientCert = ClientCert{
			ClientCertPEM: pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: peerCert.Raw,
			}),
			IssuerDN:     peerCert.Issuer.ToRDNSequence().String(),
			SerialNumber: peerCert.Issuer.SerialNumber,
			SubjectDN:    peerCert.Subject.ToRDNSequence().String(),
			Validity: validity{
				NotAfter:  peerCert.NotAfter,
				NotBefore: peerCert.NotBefore,
			},
		}

		rctx, err := json.Marshal(&requestCtx)
		if err != nil {
			log.Printf("error marshaling request context %s", err)
			w.WriteHeader(http.StatusInternalServerError)
			if _, err := w.Write([]byte("unexpected error handling request")); err != nil {
				panic(err)
			}
			return
		}
		r.Header.Set(RequestContextHeader, string(rctx))
		rp.ServeHTTP(w, r)

		requestDuration.Update(time.Since(startTime).Seconds())
	})
}
