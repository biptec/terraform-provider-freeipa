// SPDX-License-Identifier: GPL-3.0-only

package freeipa

import (
	"errors"
	"io"
	"net/http"
	"strings"
)

type kerberosLoginRetryTransport struct {
	base http.RoundTripper
}

func (t *kerberosLoginRetryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err == nil || req == nil || req.URL == nil || req.URL.Path != "/ipa/session/login_kerberos" || !isRetryableKerberosLoginTransportError(err) {
		return resp, err
	}

	if closer, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}

	retry := req.Clone(req.Context())
	retry.Body = nil
	return t.base.RoundTrip(retry)
}

func isRetryableKerberosLoginTransportError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "server closed idle connection") ||
		strings.Contains(message, "connection reset by peer") ||
		strings.Contains(message, "broken pipe")
}
