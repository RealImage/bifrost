package bifrost

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

func ExampleRequestCertificate() {
	const timeout = 5 * time.Second

	exampleNS := uuid.MustParse("228b9676-998e-489a-8468-92d46a94a32d")
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	key, err := NewPrivateKey()
	if err != nil {
		panic(err)
	}

	cert, err := RequestCertificate(ctx, "https://bifrost-ca", exampleNS, key)
	if errors.Is(err, ErrCertificateRequestInvalid) {
		// This error is returned when the wrong namespace is used in the CSR,
		// or if the CSR is invalid.
		fmt.Println("namespace mismatch or invalid csr")
	} else if errors.Is(err, ErrCertificateRequestDenied) {
		// This error is returned when the request is denied by the CA gauntlet function.
		fmt.Println("csr denied")
	}

	// Success.
	fmt.Println(cert.Subject)
}
