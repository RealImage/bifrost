package bifrost

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

func ExampleRequestCertificate() {
	exampleNS := uuid.MustParse("228b9676-998e-489a-8468-92d46a94a32d")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// TODO: handle errors
	key, _ := NewPrivateKey()
	cert, _ := RequestCertificate(ctx, "https://bifrost-ca", exampleNS, key)
	fmt.Println(cert.Subject)
}
