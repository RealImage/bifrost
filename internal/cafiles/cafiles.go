package cafiles

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/url"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

// GetCrtUri retrieves a PEM encoded certificate from uri.
func GetCrtUri(uri string) (*x509.Certificate, error) {
	crtPem, err := getPemFile(uri)
	if err != nil {
		return nil, fmt.Errorf("error getting file %s: %w", uri, err)
	}

	crt, err := x509.ParseCertificate(crtPem)
	if err != nil {
		return nil, fmt.Errorf("error parsing certificate uri %s: %w", uri, err)
	}

	return crt, nil
}

// GetKeyUri retrieves a PEM encoded private key from uri.
func GetKeyUri(uri string) (*ecdsa.PrivateKey, error) {
	keyPem, err := getPemFile(uri)
	if err != nil {
		return nil, fmt.Errorf("error getting file %s: %w", uri, err)
	}

	key, err := x509.ParseECPrivateKey(keyPem)
	if err != nil {
		return nil, fmt.Errorf("error parsing key uri %s: %w", uri, err)
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
		pemData, err = getS3Key(url.Host, url.Path[1:])
	} else {
		pemData, err = os.ReadFile(url.Path)
	}
	if err != nil {
		return nil, fmt.Errorf("error fetching pem file: %w", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no pem data found")
	}
	return block.Bytes, nil
}

func parseUri(uri string) (*url.URL, error) {
	url, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("error parsing uri %w", err)
	}

	switch s := url.Scheme; s {
	case "", "file", "s3":
	default:
		return nil, fmt.Errorf("unknown uri scheme %s", s)
	}

	return url, nil
}

var sess = session.Must(session.NewSessionWithOptions(session.Options{
	SharedConfigState: session.SharedConfigEnable,
}))

func getS3Key(bucket, key string) ([]byte, error) {
	rawObject, err := s3.New(sess).GetObject(
		&s3.GetObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		})
	if err != nil {
		return nil, fmt.Errorf("error getting s3 object: %w", err)
	}

	body, err := io.ReadAll(rawObject.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}
