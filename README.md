# Bifrost

## Use library

Use bifrost to request a certificate from a Bifrost CA.

		go get github.com/RealImage/bifrost

```go
import (
	"crypto/ecdsa"
	"crypto/elliptic"

	"github.com/RealImage/bifrost"
)

func main() {
  // TODO: handle errors
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	crt, _ := bifrost.RequestSignature(context.Background, "https://bifrost", key, nil)
	...
}
```

## [Issuer](cmd/issuer)

### Build

    go build ./cmd/issuer

### Run CA

First create the CA material:

1. Create ECDSA P256 Private Key in PEM format:

    openssl ecparam -out key.pem -name prime256v1 -genkey -noout

2. Create 10 year self-signed certificate from the newly generated key:

		openssl req -new -key key.pem -x509 -nodes -days 3650 -out crt.pem

Then run the binary passing these new files along:

		env CRT_PEM=$(cat crt.pem) KEY_PEM=$(cat key.pem) ./issuer

