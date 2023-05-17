// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package club

import "time"

const RequestContextHeader = "x-amzn-request-context"

// RequestContext is passed to the HTTP handler as a JSON encoded header value.
type RequestContext struct {
	Authentication struct {
		ClientCert ClientCert `json:"clientCert"`
	} `json:"authentication"`
}

// ClientCert contains fields related to TLS Client Certificates.
type ClientCert struct {
	ClientCertPEM []byte   `json:"clientCertPEM"`
	IssuerDN      string   `json:"issuerDN"`
	SerialNumber  string   `json:"serialNumber"`
	SubjectDN     string   `json:"subjectDN"`
	Validity      validity `json:"validity"`
}

type validity struct {
	NotAfter  time.Time `json:"notAfter"`
	NotBefore time.Time `json:"notBefore"`
}
