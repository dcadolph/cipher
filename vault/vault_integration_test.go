//go:build integration

// Integration tests for the Vault Transit backend. Skipped unless
// VAULT_ADDR and VAULT_TOKEN are present in the environment. The
// integration CI job points these at a vault service container
// running in dev mode. Local runs work with any vault server that
// has the transit secrets engine enabled at "transit/".
package vault_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dcadolph/cipher"
	"github.com/dcadolph/cipher/vault"
)

const (
	testKeyName     = "cipher-integration"
	transitMountAPI = "/v1/sys/mounts/transit"
)

// TestVaultIntegrationRoundTrip encrypts a plaintext file via the
// vault transit backend, then decrypts it and checks the bytes match.
// Catches API drift between cipher, sops, and vault transit that
// shape-only unit tests cannot.
func TestVaultIntegrationRoundTrip(t *testing.T) {
	addr, token := vaultEnv(t)

	if err := mountTransit(addr, token); err != nil {
		t.Fatalf("mount transit: %v", err)
	}
	if err := createKey(addr, token, testKeyName); err != nil {
		t.Fatalf("create key: %v", err)
	}

	uri := strings.TrimRight(addr, "/") + "/v1/transit/keys/" + testKeyName
	kp, err := vault.NewProvider(uri)
	if err != nil {
		t.Fatalf("vault.NewProvider: %v", err)
	}

	plain := []byte("api_key: sk-prod-integration-2026\n")
	enc := cipher.NewEncoder(kp)
	ciphertext, err := enc.Encode(context.Background(), "secrets.yaml", plain)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if bytes.Contains(ciphertext, []byte("sk-prod-integration-2026")) {
		t.Fatal("plaintext leaked into ciphertext")
	}

	dec := cipher.NewDecoder()
	round, err := dec.Decode(context.Background(), "secrets.yaml", ciphertext)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(plain, round) {
		t.Errorf("round-trip mismatch\n want: %q\n  got: %q", plain, round)
	}
}

// vaultEnv returns the vault address and token. Skips the test when
// either is missing so non-integration runs do not fail.
func vaultEnv(t *testing.T) (string, string) {
	t.Helper()
	addr := os.Getenv("VAULT_ADDR")
	token := os.Getenv("VAULT_TOKEN")
	if addr == "" || token == "" {
		t.Skip("set VAULT_ADDR and VAULT_TOKEN to run vault integration tests")
	}
	if err := waitReady(addr, 30*time.Second); err != nil {
		t.Fatalf("vault not ready at %s: %v", addr, err)
	}
	return addr, token
}

// waitReady polls the vault /v1/sys/health endpoint until it responds
// with 200, 429, or 472 (all of which indicate the API is up). Times
// out after d.
func waitReady(addr string, d time.Duration) error {
	deadline := time.Now().Add(d)
	url := strings.TrimRight(addr, "/") + "/v1/sys/health"
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			switch resp.StatusCode {
			case http.StatusOK, http.StatusTooManyRequests, 472, 473:
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for %s", url)
}

// mountTransit enables the transit secrets engine at the default
// path. Treats "path is already in use" as success so the test is
// idempotent across reruns on the same vault.
func mountTransit(addr, token string) error {
	body := strings.NewReader(`{"type":"transit"}`)
	resp, err := vaultRequest(http.MethodPost, addr+transitMountAPI, token, body)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
		return nil
	}
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusBadRequest &&
		bytes.Contains(raw, []byte("path is already in use")) {
		return nil
	}
	return fmt.Errorf("mount transit: status %d: %s", resp.StatusCode, raw)
}

// createKey creates a transit key with the given name. Treats an
// existing key as success.
func createKey(addr, token, name string) error {
	url := strings.TrimRight(addr, "/") + "/v1/transit/keys/" + name
	resp, err := vaultRequest(http.MethodPost, url, token, nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
		return nil
	}
	raw, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("create key %s: status %d: %s", name, resp.StatusCode, raw)
}

// vaultRequest issues an authenticated HTTP request against vault.
func vaultRequest(method, url, token string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return http.DefaultClient.Do(req)
}
