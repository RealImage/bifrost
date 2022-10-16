package bifrost

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math"
	"math/big"
	"net/http"
	"time"

	"github.com/VictoriaMetrics/metrics"
	"github.com/google/uuid"
)

const (
	// Supported Algorithms
	SignatureAlgorithm = x509.ECDSAWithSHA256
	PublicKeyAlgorithm = x509.ECDSA

	ctHeader = "Content-Type"
	ctPlain  = "text/plain"
	ctOctet  = "application/octet-stream"

	// 730 hours is ~ 1 month
	defaultIssueDuration = time.Duration(730)
)

var (
	// Metrics captures metrics on bifrost execution
	Metrics = metrics.NewSet()

	requestDuration = Metrics.NewSummary("bifrost_requests_duration_seconds")
)

// CA is the world's simplest Certificate Authority.
// The only supported operation is to issue client certificates.
// Client certificates are signed by the configured root certificate and private key.
//
// Client Certificate Template:
//
// Issuer is set to the Subject of the root certificate.
// Subject CommonName is set to the UUID of the client public key.
// Signature Algorithm: ECDSA with SHA256
// PublicKey Algorithm: ECDSA
// KeyUsage: DigitalSignature | KeyEncipherment | DataEncipherment
// ExtendedKeyUsage: ClientAuth
// NotBefore: now
// NotAfter: 1 month from now (default)
type CA struct {
	Crt *x509.Certificate
	Key *ecdsa.PrivateKey

	// IdentityNamespace is the identity namespace for this CA.
	// If unset, Namespace is used.
	IdentityNamespace uuid.UUID

	// IssueDuration is the duration of the certificate's validity starting at the time of issue.
	// If zero, the default value is used.
	IssueDuration time.Duration
}

// ServeHTTP issues a certificate if a valid certificate request is read from the request.
//
// Requests carrying a content-type of "text/plain" should have a PEM encoded certificate request.
// Requests carrying a content-type of "application/octet-stream" should submit the ASN.1 DER
// encoded form instead.
//
// Request [metrics](https://github.com/VictoriaMetrics/metrics) are exposed via `bifrost.Metrics`.
func (c CA) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

	if csr.SignatureAlgorithm != SignatureAlgorithm {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "unsupported signature algorithm: %s, use %s instead\n",
			csr.SignatureAlgorithm, SignatureAlgorithm)
		return
	}
	if csr.PublicKeyAlgorithm != PublicKeyAlgorithm {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "unsupported public key algorithm: %s, use %s instead\n",
			csr.PublicKeyAlgorithm, PublicKeyAlgorithm)
		return
	}

	// this should not fail because of the above check
	ecdsaPubKey := csr.PublicKey.(*ecdsa.PublicKey)

	// use bifrost id namespace if empty
	idNamespace := c.IdentityNamespace
	if idNamespace == uuid.Nil {
		idNamespace = Namespace
	}

	clientID := UUID(idNamespace, *ecdsaPubKey).String()
	if subName := csr.Subject.CommonName; clientID != csr.Subject.CommonName {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, "subject common name is %s but should be %s, wrong namespace?\n", subName, clientID)
		return
	}

	serialNumber, err := rand.Int(rand.Reader, big.NewInt(int64(math.MaxInt64)))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "random error\n")
		log.Printf("error creating random certificate serial: %s\n", err)
		return
	}

	// set default issue duration if empty
	issueDuration := c.IssueDuration
	if issueDuration == 0 {
		issueDuration = defaultIssueDuration
	}

	// calculate expiry
	notBefore := time.Now()
	notAfter := notBefore.Add(issueDuration)

	clientCertTemplate := x509.Certificate{
		Issuer:  c.Crt.Subject,
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

	crt, err := x509.CreateCertificate(rand.Reader, &clientCertTemplate, c.Crt, csr.PublicKey, c.Key)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "unexpected error creating certificate\n")
		log.Printf("error creating certificate %s\n", err)
		return
	}

	w.Header().Set(ctHeader, contentType)

	if contentType == ctOctet {
		if _, err := fmt.Fprint(w, crt); err != nil {
			log.Printf("error writing der cert response %s\n", err)
		}
		return
	}

	// send crt pem
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
