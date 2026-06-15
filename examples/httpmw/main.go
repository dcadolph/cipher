// Package main demonstrates cipher/httpmw. A tiny HTTP server wraps a
// plain handler with EncryptResponseBody, which encrypts every 2xx
// body to the configured age recipient. The client decrypts the
// response locally and prints the recovered plaintext.
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"

	"github.com/dcadolph/cipher"
	"github.com/dcadolph/cipher/age"
	"github.com/dcadolph/cipher/httpmw"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

// run wires the example end to end and returns any error so deferred
// cleanups (httptest server close, response body close) execute even
// on the failure path.
func run() error {
	ctx := context.Background()

	id, err := age.GenerateIdentity()
	if err != nil {
		return fmt.Errorf("generate age identity: %w", err)
	}
	if err := os.Setenv("SOPS_AGE_KEY", id.Secret); err != nil {
		return fmt.Errorf("set SOPS_AGE_KEY: %w", err)
	}

	provider, err := age.NewProvider(id.Recipient)
	if err != nil {
		return fmt.Errorf("age provider: %w", err)
	}
	enc := cipher.NewEncoder(provider)

	plainHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("payload: hello-from-server\n"))
	})

	pathFn := func(_ *http.Request) string { return "secrets.yaml" }
	wrapped := httpmw.EncryptResponseBody(enc, pathFn)(plainHandler)

	srv := httptest.NewServer(wrapped)
	defer srv.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/whatever", http.NoBody)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("do: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	fmt.Printf("encrypted response (%d bytes):\n%s\n", len(body), body)

	dec := cipher.NewDecoder()
	plain, err := dec.Decode(ctx, "secrets.yaml", body)
	if err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	fmt.Printf("\ndecoded plaintext:\n%s", plain)
	return nil
}
