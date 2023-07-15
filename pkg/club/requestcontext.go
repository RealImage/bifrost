// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package club

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/RealImage/bifrost"
	"github.com/google/uuid"
)

type RequestContext struct {
	Namespace         uuid.UUID
	ClientCertificate *x509.Certificate
	ClientPublicKey   *ecdsa.PublicKey
	SourceIP          string `json:"sourceIp"`
	UserAgent         string `json:"userAgent"`
}

func (r RequestContext) MarshalJSON() ([]byte, error) {
	return json.Marshal(requestContext{
		Identity: identity{
			SourceIP:   r.SourceIP,
			UserAgent:  r.UserAgent,
			ClientCert: r.getClientCert(),
		},
	})
}

func (r *RequestContext) UnmarshalJSON(data []byte) error {
	var rc requestContext
	if err := json.Unmarshal(data, &rc); err != nil {
		return err
	}
	r.SourceIP = rc.Identity.SourceIP
	r.UserAgent = rc.Identity.UserAgent
	if rc.Identity.ClientCert.ClientCertPem != nil {
		block, _ := pem.Decode(rc.Identity.ClientCert.ClientCertPem)
		if block == nil {
			return fmt.Errorf("failed to decode client certificate PEM")
		}
		ns, crt, key, err := bifrost.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}
		r.Namespace = ns
		r.ClientCertificate = crt
		r.ClientPublicKey = key
		r.SourceIP = rc.Identity.SourceIP
		r.UserAgent = rc.Identity.UserAgent
	}
	return nil
}

func (r RequestContext) getClientCert() clientCert {
	if r.ClientCertificate == nil {
		return clientCert{}
	}
	return clientCert{
		ClientCertPem: pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: r.ClientCertificate.Raw,
		}),
		IssuerDN:     r.ClientCertificate.Issuer.ToRDNSequence().String(),
		SerialNumber: r.ClientCertificate.Issuer.SerialNumber,
		SubjectDN:    r.ClientCertificate.Subject.ToRDNSequence().String(),
		Validity: validity{
			NotAfter:  r.ClientCertificate.NotAfter,
			NotBefore: r.ClientCertificate.NotBefore,
		},
	}
}

// RequestContext is passed to the HTTP handler as a JSON encoded header value.
type requestContext struct {
	Identity identity `json:"identity"`
}

type identity struct {
	SourceIP   string     `json:"sourceIp"`
	UserAgent  string     `json:"userAgent"`
	ClientCert clientCert `json:"clientCert"`
}

// clientCert contains fields related to TLS Client Certificates.
type clientCert struct {
	ClientCertPem []byte   `json:"clientCertPem"`
	IssuerDN      string   `json:"issuerDN"`
	SerialNumber  string   `json:"serialNumber"`
	SubjectDN     string   `json:"subjectDN"`
	Validity      validity `json:"validity"`
}

type validity struct {
	NotAfter  time.Time `json:"notAfter"`
	NotBefore time.Time `json:"notBefore"`
}
