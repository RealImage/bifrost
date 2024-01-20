// Package tinyca implements a Certificate Authority that issues certificates
// for client authentication.
package tinyca

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
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
// The only supported operation is to issue client certificates.
// Client certificates are signed by the configured root certificate and private key.
type CA struct {
	cert *bifrost.Certificate
	key  *bifrost.PrivateKey
	// dur is the duration for which the issued certificate is valid.
	dur time.Duration

	// metrics
	issuedTotal      *metrics.Counter
	requestsTotal    *metrics.Counter
	requestsDuration *metrics.Histogram
}

// New returns a new CA.
// The CA issues certificates for the given namespace.
func New(cert *bifrost.Certificate, key *bifrost.PrivateKey, dur time.Duration) (*CA, error) {
	iss := bfMetricName("issued_certs_total", cert.Namespace)
	rt := bfMetricName("requests_total", cert.Namespace)
	rd := bfMetricName("requests_duration_seconds", cert.Namespace)

	return &CA{
		cert: cert,
		key:  key,
		dur:  dur,

		issuedTotal:      bifrost.StatsForNerds.NewCounter(iss),
		requestsTotal:    bifrost.StatsForNerds.NewCounter(rt),
		requestsDuration: bifrost.StatsForNerds.NewHistogram(rd),
	}, nil
}

func bfMetricName(name string, ns uuid.UUID) string {
	return fmt.Sprintf(`bifrost_ca_%s{ns="%s"}`, name, ns)
}

// ServeHTTP issues a certificate if a valid certificate request is read from the request.
//
// Requests carrying a content-type of "text/plain" should have a PEM encoded certificate request.
// Requests carrying a content-type of "application/octet-stream" should submit the ASN.1 DER
// encoded form instead.
func (ca CA) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ca.requestsTotal.Inc()
	startTime := time.Now()

	if r.Method != http.MethodPost {
		http.Error(w, fmt.Sprintf("method %s not allowed", r.Method), http.StatusMethodNotAllowed)
		return
	}

	contentType, _, err := webapp.GetContentType(r.Header, webapp.MimeTypeText)
	if err != nil {
		e := fmt.Sprintf("error parsing Content-Type header: %s", err)
		http.Error(w, e, http.StatusBadRequest)
		return
	}

	if ct := contentType; ct != webapp.MimeTypeText && ct != webapp.MimeTypeBytes {
		msg := fmt.Sprintf("unsupported Content-Type %s", ct)
		http.Error(w, msg, http.StatusUnsupportedMediaType)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	csr, err := readCsr(contentType, body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	keyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	extKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	cert, err := ca.IssueCertificate(csr, keyUsage, extKeyUsage)
	if err != nil {
		statusCode := http.StatusInternalServerError
		if errors.Is(err, bifrost.ErrCertificateRequestInvalid) {
			statusCode = http.StatusBadRequest
		}
		if errors.Is(err, bifrost.ErrNamespaceMismatch) {
			statusCode = http.StatusForbidden
		}
		http.Error(w, err.Error(), statusCode)
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
	fmt.Println(r.Header)

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
		slog.Error("error writing certificate response", "err", err)
	}

	ca.requestsDuration.Update(time.Since(startTime).Seconds())
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

// IssueCertificate issues a client certificate for a certificate request.
// The certificate is issued with the Subject Common Name set to the
// UUID of the client public key and the Subject Organization
// set to the identity namespace UUID.
func (ca CA) IssueCertificate(
	asn1Data []byte,
	keyUsage x509.KeyUsage,
	extKeyUsage []x509.ExtKeyUsage,
) ([]byte, error) {
	csr, err := bifrost.ParseCertificateRequest(asn1Data)
	if err != nil {
		return nil, err
	}

	if csr.Namespace != ca.cert.Namespace {
		return nil, bifrost.ErrNamespaceMismatch
	}

	serialNumber, err := rand.Int(rand.Reader, big.NewInt(int64(math.MaxInt64)))
	if err != nil {
		return nil, fmt.Errorf("bifrost: unexpected error generating certificate serial: %w", err)
	}

	// Client certificate template.
	notBefore := time.Now()
	template := x509.Certificate{
		SignatureAlgorithm: bifrost.SignatureAlgorithm,
		PublicKeyAlgorithm: bifrost.PublicKeyAlgorithm,
		KeyUsage:           keyUsage,
		ExtKeyUsage:        extKeyUsage,
		Issuer:             ca.cert.Issuer,
		Subject: pkix.Name{
			Organization: []string{ca.cert.Namespace.String()},
			CommonName:   csr.PublicKey.UUID(ca.cert.Namespace).String(),
		},
		PublicKey:             csr.PublicKey,
		Signature:             csr.Signature,
		SerialNumber:          serialNumber,
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(ca.dur),
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		ca.cert.Certificate,
		csr.PublicKey,
		ca.key,
	)
	if err != nil {
		return nil, err
	}

	ca.issuedTotal.Inc()
	return certBytes, nil
}
