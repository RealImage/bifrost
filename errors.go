package bifrost

import "errors"

// Errors.
var (
	// ErrCertificateInvalid is returned when an invalid certificate is parsed.
	ErrCertificateInvalid = errors.New("bifrost: certificate invalid")

	// ErrCertificateRequestDenied is returned when a certificate request is denied by the CA Gauntlet.
	ErrCertificateRequestDenied = errors.New("bifrost: certificate request denied")

	// ErrCertificateRequestInvalid is returned when an invalid certificate request is parsed.
	ErrCertificateRequestInvalid = errors.New("bifrost: certificate request invalid")
)
