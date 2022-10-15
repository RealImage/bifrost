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

// CA is the world's simplest Certificate Authority.
// The only supported operation is to issue client certificates.
// Client certificates are signed by the configured root certificate and private key.
// and self signed root certificate configured.
// The root certificate and private key are not validated. This is your responsibility.
type CA struct {
	Crt *x509.Certificate
	Key *ecdsa.PrivateKey

	// IdentityNamespace is the identity namespace for this CA.
	// If unset, NamespaceBifrost is used.
	IdentityNamespace uuid.UUID

	// IssueDuration is the duration of the certificate's validity starting at the time of issue.
	// If zero, the default value is used.
	IssueDuration time.Duration
}

// IssueCertificate issues a certificate if a valid certificate request is read from the request.
//
// Requests carrying a content-type of "text/plain" should have a PEM encoded certificate request.
// Requests carrying a content-type of "application/octet-stream" should submit the ASN.1 DER
// encoded form instead.
//
// Certificate Template:
// Issuer is Subject of the root certificate
// Subject CommonName alone is set to the UUID of the client public key
// Signature Algorithm: ECDSA with SHA256
// PublicKey Algorithm: ECDSA
// KeyUsage: DigitalSignature | KeyEncipherment | DataEncipherment
// ExtendedKeyUsage: ClientAuth
// NotBefore: now
// NotAfter: 1 month from now
func (c *CA) IssueCertificate(w http.ResponseWriter, r *http.Request) {
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

	// set default id namespace if empty
	if c.IdentityNamespace == uuid.Nil {
		c.IdentityNamespace = NamespaceBifrost
	}

	clientID := UUID(c.IdentityNamespace, *ecdsaPubKey).String()
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
	if c.IssueDuration == 0 {
		c.IssueDuration = defaultIssueDuration
	}

	// calculate expiry
	notBefore := time.Now()
	notAfter := notBefore.Add(c.IssueDuration)

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
