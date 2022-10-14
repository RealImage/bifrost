package cafiles

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

// GetCrtUri retrieves a PEM encoded certificate from uri.
func GetCrtUri(uri string) (*x509.Certificate, error) {
	crtPem, err := getPemFile(uri)
	if err != nil {
		return nil, err
	}

	crt, err := x509.ParseCertificate(crtPem)
	if err != nil {
		return nil, fmt.Errorf("error parsing certificate: %w", err)
	}

	return crt, nil
}

// GetKeyUri retrieves a PEM encoded private key from uri.
func GetKeyUri(uri string) (*ecdsa.PrivateKey, error) {
	keyPem, err := getPemFile(uri)
	if err != nil {
		return nil, err
	}

	key, err := x509.ParseECPrivateKey(keyPem)
	if err != nil {
		return nil, fmt.Errorf("error parsing key: %w", err)
	}

	return key, nil
}

func getPemFile(uri string) ([]byte, error) {
	url, err := parseUri(uri)
	if err != nil {
		return nil, err
	}
	var pemData []byte
	if url.Scheme == "s3" {
		pemData, err = getS3File(url.Path)
	} else {
		pemData, err = os.ReadFile(url.Path)
	}
	if err != nil {
		return nil, fmt.Errorf("error fetching pem file")
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no pem data found")
	}
	return block.Bytes, nil
}

func getS3File(urlpath string) ([]byte, error) {
	urlparts := strings.Split(urlpath, "/")
	bucket := urlparts[0]
	key := strings.Join(urlparts[1:], "/")
	sess := session.Must(session.NewSession(&aws.Config{}))
	svc := s3.New(sess)

	rawObject, err := svc.GetObject(
		&s3.GetObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		})
	if err != nil {
		return nil, err
	}

	body, err := io.ReadAll(rawObject.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func parseUri(uri string) (*url.URL, error) {
	url, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("error parsing uri %s: %w", url, err)
	}

	switch s := url.Scheme; s {
	case "", "file", "s3":
	default:
		return nil, fmt.Errorf("unknown uri scheme %s", s)
	}

	return url, nil
}
