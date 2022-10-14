package bifrost

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"time"
)

const (
	// Supported Algorithms
	SignatureAlgorithm = x509.ECDSAWithSHA256
	PublicKeyAlgorithm = x509.ECDSA

	ctHeader = "Content-Type"
	ctPlain  = "text/plain"
	ctOctet  = "application/octet-stream"
)

// CA is the world's simplest Certificate Authority.
//
// The only operation supported is issuing certificates signed by the single private key
// and self signed root certificate configured.
type CA struct {
	Crt x509.Certificate
	Key ecdsa.PrivateKey
}

// IssueCertificate issues a certificate if a valid certificate request is read from the request.
//
// Requests carrying a content-type of "text/plain" should have a PEM encoded certificate request.
// Requests carrying a content-type of "application/octet-stream" should submit the ASN.1 DER
// encoded form instead.
func (c *CA) IssueCertificate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(w, "method %s not allowed", r.Method)
		return
	}

	contentType := r.Header.Get(ctHeader)
	switch contentType {
	case ctPlain, ctOctet:
	default:
		w.WriteHeader(http.StatusUnsupportedMediaType)
		fmt.Fprintf(w, "unsupported content type %s", contentType)
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

	clientCertTemplate := x509.Certificate{
		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,

		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,

		SerialNumber: big.NewInt(2),
		Issuer:       c.Crt.Subject,
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	crt, err := x509.CreateCertificate(rand.Reader, &clientCertTemplate, &c.Crt, csr.PublicKey, &c.Key)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "unexpected error creating certificate: %s\n", err)
		return
	}

	w.Header().Set("Content-Type", contentType)

	if contentType == "application/octet-stream" {
		if _, err := fmt.Fprint(w, crt); err != nil {
			log.Printf("error writing cert response %s\n", err)
		}
		return
	}

	// encode crt as pem and send
	if err := pem.Encode(w, &pem.Block{Bytes: crt}); err != nil {
		log.Printf("error writing cert response %s\n", err)
	}
}

func readCSR(contentType string, body []byte) (*x509.CertificateRequest, error) {
	csr := body
	switch contentType {
	case "application/octet-stream":
		// der
	case "text/plain":
		// pem
		block, _ := pem.Decode(body)
		if block == nil {
			return nil, fmt.Errorf("error decoding csr pem")
		}
		csr = block.Bytes
	}
	return x509.ParseCertificateRequest(csr)
}
