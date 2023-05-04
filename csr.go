// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package bifrost

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"net/http"

	"github.com/google/uuid"
)

// RequestCertificate sends a certificate request to url and returns the signed certificate.
func RequestCertificate(
	ctx context.Context,
	url string,
	ns uuid.UUID,
	key *ecdsa.PrivateKey,
) (*x509.Certificate, error) {
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: UUID(ns, &key.PublicKey).String(),
		},
		SignatureAlgorithm: SignatureAlgorithm,
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		return nil, fmt.Errorf("error creating certificate request: %w", err)
	}

	resp, err := http.Post(url, "application/octet-stream", bytes.NewReader(csr))
	if err != nil {
		return nil, fmt.Errorf("error POSTing certificate request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unexpected error reading response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected response status: %d %s\nbody: %s",
			resp.StatusCode, resp.Status, body)
	}

	cert, err := x509.ParseCertificate(body)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// X509ToTLSCertificate puts an x509.Certificate inside a tls.Certificate.
func X509ToTLSCertificate(crt *x509.Certificate, key *ecdsa.PrivateKey) *tls.Certificate {
	return &tls.Certificate{
		Certificate: [][]byte{
			crt.Raw,
		},
		PrivateKey: key,
		Leaf:       crt,
	}
}
