package inspect

import (
	"fmt"
	"strings"
)

// encapHeaders holds the raw encapsulated HTTP header sections and the matching
// ICAP Encapsulated header value describing their offsets.
type encapHeaders struct {
	bytes []byte
	value string
}

func (e encapHeaders) encapsulatedValue() string { return e.value }

// encapsulatedHTTPHeaders synthesizes the encapsulated HTTP message headers for
// the chosen ICAP method and computes the Encapsulated offset list.
//
// RESPMOD wraps the payload as an HTTP response body (req-hdr + res-hdr +
// res-body); REQMOD wraps it as an HTTP request body (req-hdr + req-body).
func encapsulatedHTTPHeaders(method Method, meta TransferMeta, originHost string) encapHeaders {
	url := meta.URL
	if url == "" {
		if meta.Filename != "" {
			url = "/" + strings.TrimPrefix(meta.Filename, "/")
		} else {
			url = "/"
		}
	}

	if method == REQMOD {
		var reqHdr strings.Builder
		fmt.Fprintf(&reqHdr, "POST %s HTTP/1.1\r\n", url)
		fmt.Fprintf(&reqHdr, "Host: %s\r\n", originHost)
		if meta.ContentType != "" {
			fmt.Fprintf(&reqHdr, "Content-Type: %s\r\n", meta.ContentType)
		}
		reqHdr.WriteString("\r\n")
		b := []byte(reqHdr.String())
		return encapHeaders{
			bytes: b,
			value: fmt.Sprintf("req-hdr=0, req-body=%d", len(b)),
		}
	}

	// RESPMOD (default).
	var reqHdr strings.Builder
	fmt.Fprintf(&reqHdr, "GET %s HTTP/1.1\r\n", url)
	fmt.Fprintf(&reqHdr, "Host: %s\r\n", originHost)
	reqHdr.WriteString("\r\n")

	var resHdr strings.Builder
	resHdr.WriteString("HTTP/1.1 200 OK\r\n")
	if meta.ContentType != "" {
		fmt.Fprintf(&resHdr, "Content-Type: %s\r\n", meta.ContentType)
	}
	resHdr.WriteString("\r\n")

	req := []byte(reqHdr.String())
	res := []byte(resHdr.String())
	return encapHeaders{
		bytes: append(append([]byte{}, req...), res...),
		value: fmt.Sprintf("req-hdr=0, res-hdr=%d, res-body=%d", len(req), len(req)+len(res)),
	}
}
