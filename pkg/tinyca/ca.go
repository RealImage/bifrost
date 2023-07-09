// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package tinyca implements a Certificate Authority that issues certificates
// for client authentication.
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
	"math"
	"math/big"
	"net/http"
	"time"

	"github.com/RealImage/bifrost"
	"github.com/RealImage/bifrost/internal/stats"
	"github.com/google/uuid"
	"golang.org/x/exp/slog"
)

const (
	acHeader      = "Accept"
	ctHeader      = "Content-Type"
	mimeTypeText  = "text/plain"
	mimeTypeBytes = "application/octet-stream"
)

// Metrics.
var (
	issuedCertsTotal = stats.ForNerds.NewCounter("bifrost_ca_issued_certs_total")
	requestsTotal    = stats.ForNerds.NewCounter("bifrost_ca_requests_total")
	requestsDuration = stats.ForNerds.NewHistogram("bifrost_ca_requests_duration_seconds")
)

// New returns a new CA.
// The CA issues certificates for the given namespace.
func New(crt *x509.Certificate, key *ecdsa.PrivateKey, dur time.Duration) (*CA, error) {
	ns, _, err := bifrost.ValidateCertificate(crt)
	if err != nil {
		return nil, fmt.Errorf("ca certificate is not a bifrost certificate: %w", err)
	}
	return &CA{
		ns:  ns,
		crt: crt,
		key: key,
		dur: dur,
	}, nil
}

// CA is a simple Certificate Authority.
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

func (ca CA) String() string {
	return fmt.Sprintf(
		"CA(ns=%s, crt=%s, keyid=%s, dur=%s)",
		ca.ns,
		ca.crt.Subject,
		bifrost.UUID(ca.ns, &ca.key.PublicKey),
		ca.dur,
	)
}

// ServeHTTP issues a certificate if a valid certificate request is read from the request.
//
// Requests carrying a content-type of "text/plain" should have a PEM encoded certificate request.
// Requests carrying a content-type of "application/octet-stream" should submit the ASN.1 DER
// encoded form instead.
func (ca CA) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestsTotal.Inc()
	startTime := time.Now()

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(w, "method %s not allowed", r.Method)
		return
	}

	contentType := r.Header.Get(ctHeader)
	switch contentType {
	case "":
		contentType = mimeTypeText
	case mimeTypeText, mimeTypeBytes:
	default:
		w.WriteHeader(http.StatusUnsupportedMediaType)
		fmt.Fprintf(w, "unsupported Content-Type %s", contentType)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "unexpected error reading request\n")
		slog.Error("error reading request body", "err", err)
		return
	}
	csr, err := readCSR(contentType, body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "error reading csr\n")
		slog.Error("error reading csr", "err", err)
		return
	}
	crt, err := ca.IssueCertificate(csr)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, bifrost.ErrCertificateFormat) {
			status = http.StatusBadRequest
		} else if errors.Is(err, bifrost.ErrWrongNamespace) {
			status = http.StatusForbidden
		}
		w.WriteHeader(status)
		fmt.Fprintf(w, "%s\n", err.Error())
		slog.Error("error issuing certificate", "err", err)
		return
	}

	accept := r.Header.Get(acHeader)
	if accept == "" || accept == "*/*" {
		accept = contentType
	}
	switch accept {
	case mimeTypeText:
		w.Header().Set(ctHeader, accept)
		err = pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: crt})
	case mimeTypeBytes:
		w.Header().Set(ctHeader, accept)
		_, err = w.Write(crt)
	default:
		w.WriteHeader(http.StatusNotAcceptable)
		fmt.Fprintf(w, "media type %s unacceptable\n", accept)
		return
	}
	if err != nil {
		slog.Error("error writing certificate response", "err", err)
	}
	requestsDuration.Update(time.Since(startTime).Seconds())
}

func readCSR(contentType string, body []byte) (*x509.CertificateRequest, error) {
	csr := body
	switch contentType {
	case mimeTypeBytes:
		// DER encoded
	case "", mimeTypeText:
		// PEM
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
// The CSR Subject Common Name must be set to the client ID.
// The certificate is issued with the Subject Common Name set to the client ID
// and the Subject Organization set to the identity namespace.
func (ca CA) IssueCertificate(csr *x509.CertificateRequest) ([]byte, error) {
	if csr.SignatureAlgorithm != bifrost.SignatureAlgorithm {
		return nil, fmt.Errorf("%w: invalid signature algorithm %s, use %s instead",
			bifrost.ErrCertificateFormat, csr.SignatureAlgorithm, bifrost.SignatureAlgorithm)
	}
	if csr.PublicKeyAlgorithm != bifrost.PublicKeyAlgorithm {
		return nil, fmt.Errorf("%w: invalid public key algorithm %s, use %s instead",
			bifrost.ErrCertificateFormat, csr.PublicKeyAlgorithm, bifrost.PublicKeyAlgorithm)
	}

	// This should not fail because of the above check.
	ecdsaPubKey := csr.PublicKey.(*ecdsa.PublicKey)

	clientID := bifrost.UUID(ca.ns, ecdsaPubKey).String()
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

	// Client certificate template.
	notBefore := time.Now()
	template := x509.Certificate{
		SignatureAlgorithm: bifrost.SignatureAlgorithm,
		PublicKeyAlgorithm: bifrost.PublicKeyAlgorithm,
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},

		Issuer: ca.crt.Issuer,
		Subject: pkix.Name{
			Organization: []string{ca.ns.String()},
			CommonName:   clientID,
		},
		PublicKey:    csr.PublicKey,
		Signature:    csr.Signature,
		SerialNumber: serialNumber,
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(ca.dur),
	}

	crtBytes, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		ca.crt,
		csr.PublicKey,
		ca.key,
	)
	if err != nil {
		return nil, err
	}
	issuedCertsTotal.Inc()
	return crtBytes, nil
}
