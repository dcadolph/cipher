package httpmw_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dcadolph/cipher"
	"github.com/dcadolph/cipher/ciphertest"
	"github.com/dcadolph/cipher/httpmw"
)

// TestDecryptRequestBodyRoundTrip verifies that the middleware exposes
// decrypted bytes to the downstream handler.
func TestDecryptRequestBodyRoundTrip(t *testing.T) {
	kp, _ := ciphertest.NewProvider(t)
	enc := cipher.NewEncoder(kp)
	dec := cipher.NewDecoder()

	encrypted, err := enc.Encode(context.Background(), "/secrets.yaml", []byte("foo: bar\n"))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	var seen []byte
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen = b
		w.WriteHeader(http.StatusOK)
	})
	wrapped := httpmw.DecryptRequestBody(dec, httpmw.DefaultPathFunc)(inner)

	req := httptest.NewRequest("POST", "/secrets.yaml", bytes.NewReader(encrypted))
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(string(seen), "foo: bar") {
		t.Errorf("inner body = %q, want substring \"foo: bar\"", seen)
	}
}

// TestDecryptRequestBodyBadInput verifies the 400 path for plaintext input.
func TestDecryptRequestBodyBadInput(t *testing.T) {
	kp, _ := ciphertest.NewProvider(t)
	_ = kp
	dec := cipher.NewDecoder()

	inner := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("inner handler should not be invoked")
	})
	wrapped := httpmw.DecryptRequestBody(dec, httpmw.DefaultPathFunc)(inner)

	req := httptest.NewRequest("POST", "/x.yaml", bytes.NewReader([]byte("plain: text\n")))
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// TestDecryptRequestBodyTooLarge verifies the 413 path for oversize inputs.
func TestDecryptRequestBodyTooLarge(t *testing.T) {
	kp, _ := ciphertest.NewProvider(t)
	_ = kp
	dec := cipher.NewDecoder()

	inner := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("inner handler should not be invoked")
	})
	wrapped := httpmw.DecryptRequestBody(
		dec, httpmw.DefaultPathFunc, httpmw.WithMaxBodyBytes(16),
	)(inner)

	req := httptest.NewRequest("POST", "/x.yaml", bytes.NewReader(make([]byte, 1024)))
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", rec.Code)
	}
}

// TestEncryptResponseBodyRoundTrip verifies the middleware writes
// encrypted bytes to the client.
func TestEncryptResponseBodyRoundTrip(t *testing.T) {
	kp, _ := ciphertest.NewProvider(t)
	enc := cipher.NewEncoder(kp)
	dec := cipher.NewDecoder()

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("foo: bar\n"))
	})
	wrapped := httpmw.EncryptResponseBody(enc, httpmw.DefaultPathFunc)(inner)

	req := httptest.NewRequest("GET", "/secrets.yaml", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !cipher.IsEncryptedPath("/secrets.yaml", rec.Body.Bytes()) {
		t.Fatalf("response body is not encrypted: %q", rec.Body.String())
	}
	plain, err := dec.Decode(context.Background(), "/secrets.yaml", rec.Body.Bytes())
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !strings.Contains(string(plain), "foo: bar") {
		t.Errorf("decoded response = %q, want substring \"foo: bar\"", plain)
	}
}

// TestEncryptResponseBodyEmpty verifies an empty inner response is
// forwarded unchanged.
func TestEncryptResponseBodyEmpty(t *testing.T) {
	kp, _ := ciphertest.NewProvider(t)
	enc := cipher.NewEncoder(kp)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	wrapped := httpmw.EncryptResponseBody(enc, httpmw.DefaultPathFunc)(inner)

	req := httptest.NewRequest("GET", "/x.yaml", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("body = %q, want empty", rec.Body.String())
	}
}

// TestEncryptResponseBodyPassesThroughErrorPages verifies that non-2xx
// responses are not encrypted: error pages must remain readable to
// clients, proxies, and operators tailing logs. Encrypting "500 Internal
// Server Error" would hide the failure mode.
func TestEncryptResponseBodyPassesThroughErrorPages(t *testing.T) {
	kp, _ := ciphertest.NewProvider(t)
	enc := cipher.NewEncoder(kp)

	const body = "internal error: database down"
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(body))
	})
	wrapped := httpmw.EncryptResponseBody(enc, httpmw.DefaultPathFunc)(inner)

	req := httptest.NewRequest("GET", "/x.yaml", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	if rec.Body.String() != body {
		t.Errorf("body = %q, want %q (must not be encrypted)", rec.Body.String(), body)
	}
	if cipher.IsEncryptedPath("/x.yaml", rec.Body.Bytes()) {
		t.Errorf("error-page body was encrypted: %q", rec.Body.String())
	}
}

// TestDecryptRequestBodyStripsTransferEncoding verifies that the
// middleware removes Transfer-Encoding and Content-Encoding from the
// request before passing to the inner handler. Stale framing headers
// would cause downstream proxies or libraries to mis-decode the
// plaintext we just substituted.
func TestDecryptRequestBodyStripsTransferEncoding(t *testing.T) {
	kp, _ := ciphertest.NewProvider(t)
	enc := cipher.NewEncoder(kp)
	dec := cipher.NewDecoder()

	encrypted, err := enc.Encode(context.Background(), "/x.yaml", []byte("foo: bar\n"))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	var (
		gotTE       []string
		gotTEHdr    string
		gotCEHdr    string
		innerCalled bool
	)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		innerCalled = true
		gotTE = r.TransferEncoding
		gotTEHdr = r.Header.Get("Transfer-Encoding")
		gotCEHdr = r.Header.Get("Content-Encoding")
		w.WriteHeader(http.StatusOK)
	})
	wrapped := httpmw.DecryptRequestBody(dec, httpmw.DefaultPathFunc)(inner)

	req := httptest.NewRequest("POST", "/x.yaml", bytes.NewReader(encrypted))
	req.Header.Set("Transfer-Encoding", "chunked")
	req.Header.Set("Content-Encoding", "gzip")
	req.TransferEncoding = []string{"chunked"}
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if !innerCalled {
		t.Fatal("inner handler was not invoked")
	}
	if len(gotTE) != 0 {
		t.Errorf("r.TransferEncoding = %v, want empty", gotTE)
	}
	if gotTEHdr != "" {
		t.Errorf("Transfer-Encoding header = %q, want empty", gotTEHdr)
	}
	if gotCEHdr != "" {
		t.Errorf("Content-Encoding header = %q, want empty", gotCEHdr)
	}
}
