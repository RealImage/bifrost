//go:generate stringer -linecomment -type=HeaderName
package asgard

type HeaderName int

const (
	HeaderNameClientCertLeaf HeaderName = iota // X-Amzn-Mtls-Clientcert-Leaf
	HeaderNameClientCert                       // X-Amzn-Mtls-Clientcert
)
