package tinyca

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"math/big"
	"net/http"
	"time"

	"github.com/RealImage/bifrost"
	"github.com/RealImage/bifrost/internal/stats"
	"github.com/google/uuid"
)

const (
	ctHeader = "Content-Type"
	ctPlain  = "text/plain"
	ctOctet  = "application/octet-stream"
)

// metrics
var requestDuration = stats.ForNerds.NewSummary("bifrost_ca_requests_duration_seconds")

// New returns a new CA.
// The CA issues certificates for the given namespace.
// If namespace is uuid.Nil, the CA issues certificates for the default namespace.
func New(ns uuid.UUID, crt *x509.Certificate, key *ecdsa.PrivateKey, dur time.Duration) CA {
	if ns == uuid.Nil {
		ns = bifrost.Namespace
	}
	return CA{
		ns:  ns,
		crt: crt,
		key: key,
		dur: dur,
	}
}

// CA is the world's simplest Certificate Authority.
// The only supported operation is to issue client certificates.
// Client certificates are signed by the configured root certificate and private key.
type CA struct {
	// ns is the namespace for which the CA issues certificates.
	ns  uuid.UUID
	crt *x509.Certificate
	key *ecdsa.PrivateKey
	// dur is the duration for which the issued certificate is valid.
	dur time.Duration
}

// ServeHTTP issues a certificate if a valid certificate request is read from the request.
//
// Requests carrying a content-type of "text/plain" should have a PEM encoded certificate request.
// Requests carrying a content-type of "application/octet-stream" should submit the ASN.1 DER
// encoded form instead.
//
// Request [metrics](https://github.com/VictoriaMetrics/metrics) are exposed via `bifrost.Metrics`.
func (ca CA) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(w, "method %s not allowed", r.Method)
		return
	}

	contentType := r.Header.Get(ctHeader)
	switch contentType {
	case "", ctPlain, ctOctet:
	default:
		w.WriteHeader(http.StatusUnsupportedMediaType)
		fmt.Fprintf(w, "unsupported Content-Type %s", contentType)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "unexpected error reading request\n")
		log.Printf("error reading request body: %s\n", err)
		return
	}
	csr, err := readCSR(contentType, body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "error reading csr\n")
		log.Printf("error reading csr: %s\n", err)
		return
	}
	crt, err := ca.IssueCertificate(csr)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, bifrost.ErrUnsupportedAlgorithm) {
			status = http.StatusBadRequest
		} else if errors.Is(err, bifrost.ErrWrongNamespace) {
			status = http.StatusForbidden
		}
		w.WriteHeader(status)
		fmt.Fprintf(w, "%s\n", err.Error())
		log.Println(err)
		return
	}

	w.Header().Set(ctHeader, contentType)
	if contentType == ctOctet {
		if _, err := fmt.Fprint(w, crt); err != nil {
			log.Printf("error writing der cert response %s\n", err)
		}
		return
	}
	if err := pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: crt}); err != nil {
		log.Printf("error writing pem cert response %s\n", err)
	}
	requestDuration.Update(time.Since(startTime).Seconds())
}

func readCSR(contentType string, body []byte) (*x509.CertificateRequest, error) {
	csr := body
	switch contentType {
	case ctOctet:
		// der
	case "", ctPlain:
		// pem
		block, _ := pem.Decode(body)
		if block == nil {
			return nil, fmt.Errorf("error decoding csr pem")
		}
		csr = block.Bytes
	}
	return x509.ParseCertificateRequest(csr)
}

// IssueCertificate issues a client certificate for the given CSR.
// The client ID is the UUID of the client public key.
func (ca CA) IssueCertificate(csr *x509.CertificateRequest) ([]byte, error) {
	if csr.SignatureAlgorithm != bifrost.SignatureAlgorithm {
		return nil, fmt.Errorf("%w: %s, use %s instead", bifrost.ErrUnsupportedAlgorithm,
			csr.SignatureAlgorithm, bifrost.SignatureAlgorithm)
	}
	if csr.PublicKeyAlgorithm != bifrost.PublicKeyAlgorithm {
		return nil, fmt.Errorf("%w: %s, use %s instead", bifrost.ErrUnsupportedAlgorithm,
			csr.PublicKeyAlgorithm, bifrost.PublicKeyAlgorithm)
	}

	// this should not fail because of the above check
	ecdsaPubKey := csr.PublicKey.(*ecdsa.PublicKey)

	// use bifrost id namespace if empty
	idNamespace := ca.ns
	if idNamespace == uuid.Nil {
		idNamespace = bifrost.Namespace
	}

	clientID := bifrost.UUID(idNamespace, ecdsaPubKey).String()
	if subName := csr.Subject.CommonName; clientID != csr.Subject.CommonName {
		return nil, fmt.Errorf(
			"subject common name is %s but should be %s, %w?",
			subName,
			clientID,
			bifrost.ErrWrongNamespace,
		)
	}

	serialNumber, err := rand.Int(rand.Reader, big.NewInt(int64(math.MaxInt64)))
	if err != nil {
		return nil, fmt.Errorf("unexpected error generating certificate serial: %w", err)
	}

	// calculate expiry
	notBefore := time.Now()
	notAfter := notBefore.Add(ca.dur)

	clientCertTemplate := x509.Certificate{
		Issuer:  ca.crt.Issuer,
		Subject: pkix.Name{CommonName: clientID},

		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,

		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,

		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},

		SerialNumber: serialNumber,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}

	return x509.CreateCertificate(
		rand.Reader,
		&clientCertTemplate,
		ca.crt,
		csr.PublicKey,
		ca.key,
	)
}
