package webapp

import (
	"mime"
	"net/http"

	"github.com/timewasted/go-accept-headers"
)

const (
	MimeTypeTextCharset = "text/plain; charset=utf-8"
	MimeTypeText        = "text/plain"
	MimeTypeBytes       = "application/octet-stream"
	MimeTypeAll         = "*/*"

	HeaderNameAccept      = "accept"
	HeaderNameContentType = "content-type"
)

// GetContentType returns the content type and parameters from the header.
// If the content type is not set, the defaultType is returned.
func GetContentType(h http.Header, defaultType string) (string, map[string]string, error) {
	contentType := h.Get(HeaderNameContentType)
	if contentType == "" {
		return defaultType, nil, nil
	}
	return mime.ParseMediaType(contentType)
}

// GetResponseMimeType returns the response content type based on the Accept header.
// If the Accept header is not set, the defaultType is returned.
// If the Accept header is set, the response content type is negotiated based on the mimeTypes.
func GetResponseMimeType(h http.Header, defaultType string, mimeTypes ...string) (string, error) {
	a := h.Get(HeaderNameAccept)
	if a == "" {
		return defaultType, nil
	}

	mimeTypes = append([]string{defaultType}, mimeTypes...)
	respType, err := accept.Negotiate(a, mimeTypes...)
	if err != nil {
		return "", err
	}

	if respType == "" {
		return defaultType, nil
	}

	return respType, nil
}
