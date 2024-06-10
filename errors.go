package bifrost

import "errors"

// Errors.
var (
	// ErrCertificateInvalid is returned when an invalid certificate is parsed.
	ErrCertificateInvalid = errors.New("bifrost: certificate invalid")

	// ErrRequestDenied is returned when a certificate request is denied by the CA Gauntlet.
	ErrRequestDenied = errors.New("bifrost: certificate request denied")

	// ErrRequestInvalid is returned when an invalid certificate request is parsed.
	ErrRequestInvalid = errors.New("bifrost: certificate request invalid")

	// ErrRequestAborted is returned when the CA Gauntlet function times out or panics.
	ErrRequestAborted = errors.New("bifrost: certificate request aborted")
)
