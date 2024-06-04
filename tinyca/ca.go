// Package tinyca implements a small and flexible Certificate Authority.
// The CA issues client certificates signed by a root certificate and private key.
//
// tinyca exposes a simple HTTP API to issue certificates.
// tinyca is primarily meant to issue client certificates for mTLS authentication.
//
// The CA also provides an interface to customize the certificate template.
// This allows applications to add application-specific data to issued certificates,
// along with the standard bifrost fields.
package tinyca

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/big"
	"net/http"
	"time"

	"github.com/RealImage/bifrost"
	"github.com/RealImage/bifrost/internal/webapp"
	"github.com/RealImage/bifrost/web"
	"github.com/VictoriaMetrics/metrics"
	"github.com/google/uuid"
)

// CA is a simple Certificate Authority.
// The CA issues client certificates signed by a root certificate and private key.
type CA struct {
	cert *bifrost.Certificate
	key  *bifrost.PrivateKey
	gh   *gauntletHolder

	// metrics
	requests      *metrics.Counter
	issuedTotal   *metrics.Counter
	issueDuration *metrics.Histogram
	issueSize     *metrics.Histogram
}

// New returns a new Certificate Authority.
// CA signs client certificates with the provided root certificate and private key.
// CA uses the provided gauntlet func to customise issued certificates.
func New(
	cert *bifrost.Certificate,
	key *bifrost.PrivateKey,
	gauntlet Gauntlet,
) (*CA, error) {
	if !cert.IsCA() {
		return nil, fmt.Errorf("bifrost: root certificate is not a valid CA")
	}

	reqs := bfMetricName("requests_total", cert.Namespace)
	issued := bfMetricName("issued_certs_total", cert.Namespace)
	issueDuration := bfMetricName("issue_duration_seconds", cert.Namespace)
	issueSize := bfMetricName("issue_size_bytes", cert.Namespace)

	ca := CA{
		cert: cert,
		key:  key,
		gh:   newGauntletHolder(gauntlet, cert.Namespace),

		requests:      bifrost.StatsForNerds.GetOrCreateCounter(reqs),
		issuedTotal:   bifrost.StatsForNerds.GetOrCreateCounter(issued),
		issueDuration: bifrost.StatsForNerds.GetOrCreateHistogram(issueDuration),
		issueSize:     bifrost.StatsForNerds.GetOrCreateHistogram(issueSize),
	}

	return &ca, nil
}

// ServeHTTP issues a certificate if a valid certificate request is read from the request.
//
// Requests carrying a content-type of "text/plain" should have a PEM encoded certificate request.
// Requests carrying a content-type of "application/octet-stream" should submit the ASN.1 DER
// encoded form instead.
func (ca *CA) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ca.requests.Inc()

	nb := r.URL.Query().Get("not-before")
	na := r.URL.Query().Get("not-after")

	ctx := r.Context()

	notBefore, notAfter, err := ParseValidity(nb, na)
	if err != nil {
		writeHTTPError(ctx, w, err.Error(), http.StatusBadRequest)
		return
	}

	contentType, _, err := webapp.GetContentType(r.Header, webapp.MimeTypeText)
	if err != nil {
		msg := fmt.Sprintf("error parsing Content-Type header: %s", err)
		writeHTTPError(ctx, w, msg, http.StatusBadRequest)
		return
	}

	if ct := contentType; ct != webapp.MimeTypeText && ct != webapp.MimeTypeBytes {
		msg := fmt.Sprintf("unsupported Content-Type %s", ct)
		writeHTTPError(ctx, w, msg, http.StatusUnsupportedMediaType)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeHTTPError(ctx, w, err.Error(), http.StatusInternalServerError)
		return
	}
	csr, err := readCsr(contentType, body)
	if err != nil {
		writeHTTPError(ctx, w, err.Error(), http.StatusBadRequest)
		return
	}

	cert, err := ca.IssueCertificate(csr, notBefore, notAfter)
	if err != nil {
		statusCode := http.StatusInternalServerError

		switch {
		case errors.Is(err, bifrost.ErrRequestInvalid):
			statusCode = http.StatusBadRequest
		case errors.Is(err, bifrost.ErrRequestDenied):
			statusCode = http.StatusForbidden
		case errors.Is(err, bifrost.ErrRequestAborted):
			statusCode = http.StatusServiceUnavailable
		}

		writeHTTPError(ctx, w, err.Error(), statusCode)
		return
	}

	responseType, err := webapp.GetResponseMimeType(
		r.Header,
		contentType,
		webapp.MimeTypeText,
		webapp.MimeTypeBytes,
		webapp.MimeTypeHtml,
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	switch responseType {
	case webapp.MimeTypeAll, webapp.MimeTypeText:
		w.Header().Set(webapp.HeaderNameContentType, webapp.MimeTypeTextCharset)
		err = pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
	case webapp.MimeTypeBytes:
		w.Header().Set(webapp.HeaderNameContentType, webapp.MimeTypeBytes)
		_, err = w.Write(cert)
	case webapp.MimeTypeHtml:
		w.Header().Set(webapp.HeaderNameContentType, webapp.MimeTypeHtmlCharset)
		certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
		data := map[string]any{"certPem": string(certPem)}
		err = web.Templates.ExecuteTemplate(w, "certificate.html", data)
	default:
		msg := fmt.Sprintf("media type %s unacceptable", responseType)
		http.Error(w, msg, http.StatusNotAcceptable)
		return
	}
	if err != nil {
		slog.ErrorContext(ctx, "error writing certificate response", "err", err)
	}
}

// IssueCertificate issues a client certificate for a valid certificate request parsed from asn1CSR.
func (ca *CA) IssueCertificate(asn1CSR []byte, notBefore, notAfter time.Time) ([]byte, error) {
	issueStart := time.Now()

	csr, err := bifrost.ParseCertificateRequest(asn1CSR)
	if err != nil {
		return nil, err
	}

	if csr.Namespace != ca.cert.Namespace {
		return nil, fmt.Errorf("%w, namespace mismatch", bifrost.ErrRequestInvalid)
	}

	if notBefore.IsZero() || notAfter.IsZero() || notAfter.Before(notBefore) {
		return nil, fmt.Errorf(
			"%w, invalid validity period",
			bifrost.ErrRequestInvalid,
		)
	}

	template, err := ca.gh.throw(csr)
	if err != nil {
		return nil, err
	}

	template.NotBefore = notBefore
	template.NotAfter = notAfter

	// Overwrite the fields we care about.
	if template.SerialNumber == nil {
		sn, err := rand.Int(rand.Reader, big.NewInt(int64(math.MaxInt64)))
		if err != nil {
			return nil, fmt.Errorf(
				"bifrost: unexpected error generating certificate serial: %w",
				err,
			)
		}
		template.SerialNumber = sn
	}

	template.SignatureAlgorithm = bifrost.SignatureAlgorithm
	template.Issuer = ca.cert.Issuer
	template.Subject.Organization = []string{ca.cert.Namespace.String()}
	template.Subject.CommonName = csr.PublicKey.UUID(ca.cert.Namespace).String()
	template.BasicConstraintsValid = true

	certBytes, err := x509.CreateCertificate(
		rand.Reader,
		template,
		ca.cert.Certificate,
		csr.PublicKey.PublicKey,
		ca.key,
	)
	if err != nil {
		return nil, err
	}

	ca.issueDuration.UpdateDuration(issueStart)
	ca.issueSize.Update(float64(len(certBytes)))
	ca.issuedTotal.Inc()

	return certBytes, nil
}

func readCsr(contentType string, body []byte) ([]byte, error) {
	asn1Data := body

	switch contentType {
	case webapp.MimeTypeBytes:
		// DER encoded
	case "", webapp.MimeTypeText:
		// PEM
		block, _ := pem.Decode(body)
		if block == nil {
			return nil, fmt.Errorf("bifrost: error decoding certificate request PEM block")
		}
		asn1Data = block.Bytes
	}

	return asn1Data, nil
}

func writeHTTPError(ctx context.Context, w http.ResponseWriter, msg string, statusCode int) {
	slog.ErrorContext(ctx, msg, "statusCode", statusCode)
	http.Error(w, msg, statusCode)
}

func bfMetricName(name string, ns uuid.UUID) string {
	return fmt.Sprintf(`bifrost_ca_%s{ns="%s"}`, name, ns)
}
