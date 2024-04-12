# ![Bifrost](docs/bifrost.png) Bifrost

[![Go Reference](https://pkg.go.dev/badge/github.com/RealImage/bifrost.svg)](https://pkg.go.dev/github.com/RealImage/bifrost)

A simple mTLS authentication toolkit.

[![CI 🏗](https://github.com/RealImage/bifrost/actions/workflows/ci.yml/badge.svg)](https://github.com/RealImage/bifrost/actions/workflows/ci.yml)

Bifrost consists of a Certificate Authority (CA) server that issues X.509 certificates,
a Go package to fetch such certificates, and a Go package with HTTP middleware
to identify and authenticate clients using such TLS certificates in requests.

Bifrost CA does not authenticate certificate signing
requests before issuance. You must authorise or control access to Bifrost CA as needed.

Bifrost CA issues certificates signed by a private key and a TLS X.509 certificate.
A TLS reverse proxy can use the issuing certificate to authenticate clients and secure
access to web applications.
Bifrost identifies clients uniquely by ECDSA public keys.
Client identity namespaces allow Bifrost to be natively multi-tenant.

## Releases

[![Release 🚀](https://github.com/RealImage/bifrost/actions/workflows/release.yml/badge.svg)](https://github.com/RealImage/bifrost/actions/workflows/release.yml)

Bifrost binaries are available for Windows, MacOS, and Linux on
the [releases](https://github.com/RealImage/bifrost/releases) page.

Container images are available at
[ghcr.io/realimage/bifrost](https://ghcr.io/realimage/bifrost).

## Identity

Bifrost identities are UUID version 5 UUIDs, derived from ECDSA public keys.
A client's identity is the sha1 hash of the namespace appended to the X and Y
curve points (big-endian) of its ECDSA P256 public key.

In pseudo-code,

`bifrostUUID = UUIDv5(sha1(NamespaceClientIdentity + PublicKey.X.Bytes() + PublicKey.Y.Bytes())`

## Build

### Native

Install Node.js & Go.
Build static binaries on your machine for all supported platforms.

```console
./build.sh
```

### Container

Build an image with [`ko`](https://ko.build).

```console
ko build --local ./cmd/bf
```

## Take Bifrost out for a spin

Here's what you need to get started.

1. Install all bifrost binaries by running `go install ./...`.
2. Generate a new namespace UUID using `export BF_NS=$(bf new ns)`.
3. Ensure that python, curl, and openssl are available in your environment.

### Start your engines

Set up server key material and start the CA and TLS reverse-proxy.

1. Create Bifrost ECDSA private key:

    `bf new id -o key.pem`

2. Create self-signed CA root certificate:

    `bf new ca -o cert.pem`

3. Start the CA issuer, reverse proxy, and the target web server.

    ```console
    bf ca &
    bf proxy &
    python -m http.server 8080 &
    ```

### Create a client identity

1. Generate a new client identity key:

    `bf new key -o clientkey.pem`

2. Create a Certificate Signing Request with the client private key:

    `bf new csr clientkey.pem -o csr.pem`

3. Fetch signed certificate from the CA:

   ```console
   curl -X POST -H "Content-Type: text/plain" --data-binary "@csr.pem" \
     "localhost:8888/issue" >clientcrt.pem`
   ```

4. Make a request through the mTLS proxy to the python web server:

    `curl --cert clientcrt.pem --key clientkey.pem -k https://localhost:8443`

5. Admire your shiny new client certificate (optional):

   ```console
   $ openssl x509 -in clientcrt.pem -noout -text
   Certificate:
       Data:
           Version: 3 (0x2)
           Serial Number: 871355257622038992 (0xc17acfd7bbb09d0)
           Signature Algorithm: ecdsa-with-SHA256
           Issuer: CN = 46d6516e-715f-5a8a-8523-c2924b2a53d7, O = 00000000-0000-0000-0000-000000000000
           Validity
               Not Before: Jul 12 23:09:46 2023 GMT
               Not After : Jul 13 00:09:46 2023 GMT
           Subject: O = 00000000-0000-0000-0000-000000000000, CN = 8b9fca79-13e0-5157-b754-ff2e4e985c30
           Subject Public Key Info:
               Public Key Algorithm: id-ecPublicKey
                   Public-Key: (256 bit)
                   pub:
                       04:84:4a:3b:fa:2e:dd:07:d5:a7:96:26:68:ac:81:
                       16:8a:cb:57:02:0a:c7:ae:d3:b3:da:b5:b4:2d:a5:
                       c8:65:c2:4d:88:45:00:5a:44:f3:30:52:ab:63:42:
                       59:3d:50:68:50:45:e0:60:61:e1:57:b8:5c:dc:87:
                       7f:f9:7e:07:f6
                   ASN1 OID: prime256v1
                   NIST CURVE: P-256
           X509v3 extensions:
               X509v3 Key Usage: critical
                   Digital Signature
               X509v3 Extended Key Usage: 
                   TLS Web Client Authentication
               X509v3 Authority Key Identifier: 
                   CA:2F:94:0D:43:FB:6D:00:66:09:50:4C:8C:1F:A3:BC:C1:EF:98:F4
       Signature Algorithm: ecdsa-with-SHA256
       Signature Value:
           30:45:02:21:00:a3:2a:99:6e:29:b6:97:61:55:ac:a5:96:9c:
           ab:c3:86:44:4e:86:f5:1f:56:34:49:a7:36:b5:6c:db:72:65:
           a6:02:20:14:a9:d2:07:d5:63:17:d5:e0:3b:e3:f7:ef:e7:d0:
           65:86:c3:74:5e:b4:61:87:cd:af:6a:71:af:cd:cf:45:8b
   ```

## Fishy Benchmarks

A toy benchmark for your favourite toy CA.

![Fishy Benchmark](docs/fishy-benchmark.jpg)

Bifrost CA issued 10,000 certificates on my Macbook Pro M1 Pro in ~41s.
Your results may vary.

## [LICENSE](LICENSE)

Bifrost is available under the terms of the MIT License.

Qube Cinema © 2023, 2024
