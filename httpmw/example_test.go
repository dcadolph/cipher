package httpmw_test

import (
	"io"
	"log"
	"net/http"

	"github.com/dcadolph/cipher"
	"github.com/dcadolph/cipher/age"
	"github.com/dcadolph/cipher/httpmw"
)

// ExampleDecryptRequestBody wires the middleware in front of a
// handler that expects plaintext. The middleware reads the encrypted
// body, decrypts it with the cipher.Decoder, and the handler sees
// plaintext bytes.
func ExampleDecryptRequestBody() {
	dec := cipher.NewDecoder()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_, _ = w.Write(body)
	})
	mw := httpmw.DecryptRequestBody(dec, httpmw.DefaultPathFunc)
	http.Handle("/secrets/", mw(handler))
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}

// ExampleEncryptResponseBody wraps a handler so its response is
// encrypted before reaching the client. Do not wrap handlers that
// rely on http.Flusher, http.Hijacker, or io.ReaderFrom because the
// middleware buffers the full response.
func ExampleEncryptResponseBody() {
	kp, _ := age.NewProvider("age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p")
	enc := cipher.NewEncoder(kp)
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("api_key: secret\n"))
	})
	mw := httpmw.EncryptResponseBody(enc, httpmw.DefaultPathFunc)
	http.Handle("/secrets/", mw(handler))
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
