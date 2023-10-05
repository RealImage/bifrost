// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package bifrost

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/google/uuid"
)

func ExampleRequestCertificate() {
	exampleNS := uuid.MustParse("228b9676-998e-489a-8468-92d46a94a32d")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// TODO: handle errors
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert, _ := RequestCertificate(ctx, "https://bifrost-ca", exampleNS, key)
	fmt.Println(cert.Subject)
}
