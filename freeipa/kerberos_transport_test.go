// SPDX-License-Identifier: GPL-3.0-only

package freeipa

import (
	"errors"
	"io"
	"net/http"
	"testing"
)

type scriptedRoundTripper struct {
	calls int
	errs  []error
}

func (s *scriptedRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	s.calls++
	if len(s.errs) >= s.calls && s.errs[s.calls-1] != nil {
		return nil, s.errs[s.calls-1]
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(http.NoBody)}, nil
}

func TestKerberosLoginRetryTransportRetriesStaleConnectionOnce(t *testing.T) {
	base := &scriptedRoundTripper{errs: []error{errors.New("http: server closed idle connection"), nil}}
	transport := &kerberosLoginRetryTransport{base: base}
	req, err := http.NewRequest(http.MethodPost, "https://ipa.example.test/ipa/session/login_kerberos", nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip returned error: %v", err)
	}
	if resp == nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected response: %#v", resp)
	}
	if base.calls != 2 {
		t.Fatalf("expected 2 transport calls, got %d", base.calls)
	}
}

func TestKerberosLoginRetryTransportDoesNotRetryJSONRPCMutation(t *testing.T) {
	base := &scriptedRoundTripper{errs: []error{errors.New("http: server closed idle connection")}}
	transport := &kerberosLoginRetryTransport{base: base}
	req, err := http.NewRequest(http.MethodPost, "https://ipa.example.test/ipa/session/json", nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := transport.RoundTrip(req); err == nil {
		t.Fatal("expected transport error")
	}
	if base.calls != 1 {
		t.Fatalf("JSON-RPC request must not be retried, got %d calls", base.calls)
	}
}

func TestKerberosLoginRetryTransportDoesNotRetryNonTransportFailure(t *testing.T) {
	base := &scriptedRoundTripper{errs: []error{errors.New("certificate verify failed")}}
	transport := &kerberosLoginRetryTransport{base: base}
	req, err := http.NewRequest(http.MethodPost, "https://ipa.example.test/ipa/session/login_kerberos", nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := transport.RoundTrip(req); err == nil {
		t.Fatal("expected transport error")
	}
	if base.calls != 1 {
		t.Fatalf("non-retryable error must not be retried, got %d calls", base.calls)
	}
}
