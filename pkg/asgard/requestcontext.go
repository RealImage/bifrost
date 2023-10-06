// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package asgard

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/RealImage/bifrost"
)

type keyRequestContext struct{}

const (
	DefaultRequestContextHeader = "x-amzn-request-context"
)

// FromContext returns a *RequestContext from http.Request.Context.
// If it doesn't exist (i.e. Heimdall hasn't run yet), the second
// return parameter is false.
func FromContext(ctx context.Context) (r *RequestContext, ok bool) {
	r, ok = ctx.Value(keyRequestContext{}).(*RequestContext)
	return
}

// MustFromContext is identical to FromContext, except that it panics
// if the context doesn't have a RequestContext object.
// Heimdall must have run before this function is called.
func MustFromContext(ctx context.Context) *RequestContext {
	return ctx.Value(keyRequestContext{}).(*RequestContext)
}

type RequestContext struct {
	ClientCertificate *bifrost.Certificate
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
	if rc.Identity.ClientCert.ClientCertPem == nil {
		return fmt.Errorf("client certificate PEM is nil")
	}
	block, _ := pem.Decode(rc.Identity.ClientCert.ClientCertPem)
	if block == nil {
		return fmt.Errorf("failed to decode client certificate PEM")
	}
	cert, err := bifrost.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	r.ClientCertificate = cert
	r.SourceIP = rc.Identity.SourceIP
	r.UserAgent = rc.Identity.UserAgent
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
	ClientCertPem []byte   `json:"clientCertPEM"`
	IssuerDN      string   `json:"issuerDN"`
	SerialNumber  string   `json:"serialNumber"`
	SubjectDN     string   `json:"subjectDN"`
	Validity      validity `json:"validity"`
}

type validity struct {
	NotAfter  time.Time `json:"notAfter"`
	NotBefore time.Time `json:"notBefore"`
}
