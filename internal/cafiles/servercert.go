package cafiles

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"time"

	"github.com/RealImage/bifrost"
	"github.com/RealImage/bifrost/tinyca"
)

func CreateServerCertificate(
	caCert *bifrost.Certificate,
	caKey *ecdsa.PrivateKey,
) (*bifrost.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating server key: %w", err)
	}

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   bifrost.UUID(caCert.Namespace, &key.PublicKey).String(),
			Organization: []string{caCert.Namespace.String()},
		},
		SignatureAlgorithm: bifrost.SignatureAlgorithm,
		DNSNames:           []string{"localhost"},
		IPAddresses:        []net.IP{net.ParseIP("127.0.0.0")},
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating certificate request: %w", err)
	}

	ca, err := tinyca.New(caCert, caKey, time.Hour*24*365)
	if err != nil {
		return nil, nil, err
	}

	keyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	extKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	certBytes, err := ca.IssueCertificate(csrBytes, keyUsage, extKeyUsage)
	if err != nil {
		return nil, nil, fmt.Errorf("error issuing server certificate: %w", err)
	}

	cert, err := bifrost.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing server certificate: %w", err)
	}
	return cert, key, nil
}
