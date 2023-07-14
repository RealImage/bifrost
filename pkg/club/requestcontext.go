// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package club

import (
	"crypto/x509"
	"encoding/pem"
	"time"
)

// RequestContext is passed to the HTTP handler as a JSON encoded header value.
type RequestContext struct {
	Identity Identity `json:"identity"`
}

type Identity struct {
	SourceIP   string     `json:"sourceIp"`
	UserAgent  string     `json:"userAgent"`
	ClientCert ClientCert `json:"clientCert"`
}

// ClientCert contains fields related to TLS Client Certificates.
type ClientCert struct {
	ClientCertPEM []byte   `json:"clientCertPem"`
	IssuerDN      string   `json:"issuerDN"`
	SerialNumber  string   `json:"serialNumber"`
	SubjectDN     string   `json:"subjectDN"`
	Validity      validity `json:"validity"`
}

type validity struct {
	NotAfter  time.Time `json:"notAfter"`
	NotBefore time.Time `json:"notBefore"`
}

func NewRequestContext(crt *x509.Certificate) *RequestContext {
	var r RequestContext
	r.Identity.ClientCert = ClientCert{
		ClientCertPEM: pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: crt.Raw,
		}),
		IssuerDN:     crt.Issuer.ToRDNSequence().String(),
		SerialNumber: crt.Issuer.SerialNumber,
		SubjectDN:    crt.Subject.ToRDNSequence().String(),
		Validity: validity{
			NotAfter:  crt.NotAfter,
			NotBefore: crt.NotBefore,
		},
	}
	return &r
}
