package bifrost

import (
	"context"
	"errors"
	"fmt"
	"time"
)

func ExampleRequestCertificate() {
	const timeout = 5 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	key, err := NewPrivateKey()
	if err != nil {
		panic(err)
	}

	cert, err := RequestCertificate(ctx, "https://bifrost-ca", key)
	if errors.Is(err, ErrRequestInvalid) {
		// This error is returned if the CSR is invalid.
		fmt.Println("namespace mismatch or invalid csr")
	} else if errors.Is(err, ErrRequestDenied) {
		// This error is returned when the request is denied by the CA gauntlet function.
		fmt.Println("csr denied")
	}

	// Success.
	fmt.Println(cert.Subject)
}
