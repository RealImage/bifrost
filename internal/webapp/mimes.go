package webapp

import (
	"mime"
	"net/http"

	"github.com/timewasted/go-accept-headers"
)

const (
	MimeTypeTextCharset = "text/plain; charset=utf-8"
	MimeTypeHtmlCharset = "text/html; charset=utf-8"
	MimeTypeText        = "text/plain"
	MimeTypeBytes       = "application/octet-stream"
	MimeTypeHtml        = "text/html"
	MimeTypeAll         = "*/*"

	HeaderNameAccept      = "accept"
	HeaderNameContentType = "content-type"
	HeaderNameHXRequest   = "hx-request"
)

// GetContentType returns the mime type and the parameters from the given content type.
func GetContentType(h http.Header, defaultType string) (string, map[string]string, error) {
	contentType := h.Get(HeaderNameContentType)
	if contentType == "" {
		return defaultType, nil, nil
	}
	return mime.ParseMediaType(contentType)
}

// GetResponseMimeType returns the mime type to be used for the response.
func GetResponseMimeType(h http.Header, defaultType string, mimeTypes ...string) (string, error) {
	if h.Get(HeaderNameHXRequest) == "true" {
		return MimeTypeHtmlCharset, nil
	}
	a := h.Get(HeaderNameAccept)
	if a == "" {
		return defaultType, nil
	}
	respType, err := accept.Negotiate(a, mimeTypes...)
	if err != nil {
		return "", err
	}
	return respType, nil
}
