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
	"mime"
	"net/http"
	"time"

	"github.com/RealImage/bifrost"
	"github.com/RealImage/bifrost/internal/stats"
	"github.com/google/uuid"
	"golang.org/x/exp/slog"
)

const (
	acHeaderName  = "accept"
	ctHeaderName  = "content-type"
	mimeTypeText  = "text/plain"
	mimeTypeBytes = "application/octet-stream"
	mimeTypeAll   = "*/*"

	mimeTypeTextCharset = "text/plain; charset=utf-8"
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

// ServeHTTP issues a certificate if a valid certificate request is read from the request.
//
// Requests carrying a content-type of "text/plain" should have a PEM encoded certificate request.
// Requests carrying a content-type of "application/octet-stream" should submit the ASN.1 DER
// encoded form instead.
func (ca CA) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestsTotal.Inc()
	startTime := time.Now()

	if r.Method != http.MethodPost {
		http.Error(w, fmt.Sprintf("method %s not allowed", r.Method), http.StatusMethodNotAllowed)
		return
	}

	contentType, _, err := getMimeTypeHeader(r.Header.Get(ctHeaderName), mimeTypeText)
	if err != nil {
		e := fmt.Sprintf("error parsing Content-Type header: %s", err)
		http.Error(w, e, http.StatusBadRequest)
		return
	}

	switch contentType {
	case "":
		contentType = mimeTypeText
	case mimeTypeText, mimeTypeBytes:
	default:
		http.Error(
			w,
			fmt.Sprintf("unsupported Content-Type %s", contentType),
			http.StatusUnsupportedMediaType,
		)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ns, csr, pubkey, err := readCSR(contentType, body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	crt, err := ca.IssueCertificate(ns, csr, pubkey)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, bifrost.ErrWrongNamespace) {
			status = http.StatusForbidden
		}
		http.Error(w, err.Error(), status)
		return
	}

	accept, _, err := getMimeTypeHeader(r.Header.Get(acHeaderName), contentType)
	if err != nil {
		e := fmt.Sprintf("error parsing Accept header: %s", err)
		http.Error(w, e, http.StatusBadRequest)
		return
	}

	responseMimeType := contentType
	switch accept {
	case mimeTypeAll, "":
	case mimeTypeText:
		responseMimeType = mimeTypeText
	case mimeTypeBytes:
		responseMimeType = mimeTypeBytes
	default:
		http.Error(w, fmt.Sprintf("media type %s unacceptable", accept), http.StatusNotAcceptable)
		return
	}
	if responseMimeType == mimeTypeBytes {
		w.Header().Set(ctHeaderName, mimeTypeBytes)
		_, err = w.Write(crt)
	} else {
		w.Header().Set(ctHeaderName, mimeTypeTextCharset)
		err = pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: crt})
	}

	if err != nil {
		slog.Error("error writing certificate response", "err", err)
	}
	requestsDuration.Update(time.Since(startTime).Seconds())
}

func readCSR(
	contentType string,
	body []byte,
) (uuid.UUID, *x509.CertificateRequest, *ecdsa.PublicKey, error) {
	csr := body
	switch contentType {
	case mimeTypeBytes:
		// DER encoded
	case "", mimeTypeText:
		// PEM
		block, _ := pem.Decode(body)
		if block == nil {
			return uuid.Nil, nil, nil, fmt.Errorf("error decoding csr pem")
		}
		csr = block.Bytes
	}
	return bifrost.ParseCertificateRequest(csr)
}

// IssueCertificate issues a client certificate for the given CSR.
// The client ID is the UUID of the client public key.
// The CSR Subject Common Name must be set to the client ID.
// The certificate is issued with the Subject Common Name set to the client ID
// and the Subject Organization set to the identity namespace.
func (ca CA) IssueCertificate(
	ns uuid.UUID,
	csr *x509.CertificateRequest,
	pubkey *ecdsa.PublicKey,
) ([]byte, error) {
	if ns != ca.ns {
		return nil, fmt.Errorf("%w: '%s', use '%s' instead",
			bifrost.ErrWrongNamespace, ns, ca.ns)
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
			CommonName:   bifrost.UUID(ca.ns, pubkey).String(),
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

func getMimeTypeHeader(value, defaultValue string) (string, map[string]string, error) {
	if value == "" {
		return defaultValue, nil, nil
	}
	return mime.ParseMediaType(value)
}
