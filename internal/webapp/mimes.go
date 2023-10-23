// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package webapp

import (
	"fmt"
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

// GetMimeTypeHeader returns the mime type and the parameters from the given content type.
// The first parameter is the value of the "Content-Type" header.
// The second parameter is the default mime type to be used if the "Content-Type" header is empty.
func GetMimeTypeHeader(
	h http.Header,
	headerName, defaultValue string,
) (string, map[string]string, error) {
	ct := h.Get(headerName)
	if ct == "" {
		return defaultValue, nil, nil
	}
	fmt.Println(headerName, ct)
	return mime.ParseMediaType(ct)
}

// GetResponseMimeType returns the mime type to be used for the response.
func GetResponseMimeType(h http.Header, mimeTypes ...string) (string, error) {
	if h.Get(HeaderNameHXRequest) == "true" && h.Get(HeaderNameAccept) == MimeTypeAll {
		return MimeTypeHtmlCharset, nil
	}
	respType, err := accept.Negotiate(h.Get(HeaderNameAccept), mimeTypes...)
	if err != nil {
		return "", err
	}
	return respType, nil
}
