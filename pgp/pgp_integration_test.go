//go:build integration

// Integration tests for the PGP backend. Skipped when gpg is not on
// PATH. Uses a fresh GNUPGHOME so generated keys never touch the
// caller's keyring.
package pgp_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dcadolph/cipher"
	"github.com/dcadolph/cipher/pgp"
)

// TestPGPIntegrationRoundTrip generates a throwaway RSA key in an
// isolated GNUPGHOME, encrypts a plaintext through cipher and the
// pgp provider, then decrypts the bytes and checks they match.
func TestPGPIntegrationRoundTrip(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not on PATH")
	}
	gnupgHome := t.TempDir()
	t.Setenv("GNUPGHOME", gnupgHome)

	fp := generateKey(t, gnupgHome)

	kp, err := pgp.NewProvider(fp)
	if err != nil {
		t.Fatalf("pgp.NewProvider: %v", err)
	}

	plain := []byte("api_key: sk-pgp-integration-2026\n")
	enc := cipher.NewEncoder(kp)
	ciphertext, err := enc.Encode(context.Background(), "secrets.yaml", plain)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if bytes.Contains(ciphertext, []byte("sk-pgp-integration-2026")) {
		t.Fatal("plaintext leaked into ciphertext")
	}

	dec := cipher.NewDecoder()
	round, err := dec.Decode(context.Background(), "secrets.yaml", ciphertext)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(plain, round) {
		t.Errorf("round trip mismatch\n want: %q\n  got: %q", plain, round)
	}
}

// generateKey writes a gpg batch script then asks gpg to create a
// 2048 bit RSA key with no passphrase. Returns the primary key
// fingerprint. 2048 is enough for tests and finishes in a few
// seconds even on slow CI runners.
func generateKey(t *testing.T, gnupgHome string) string {
	t.Helper()
	batch := filepath.Join(gnupgHome, "batch")
	script := []byte(`%no-protection
Key-Type: RSA
Key-Length: 2048
Name-Real: Cipher Test
Name-Email: cipher-test@example.com
Expire-Date: 0
%commit
`)
	if err := os.WriteFile(batch, script, 0o600); err != nil {
		t.Fatalf("write batch: %v", err)
	}
	if out, err := exec.Command("gpg", "--batch", "--gen-key", batch).CombinedOutput(); err != nil {
		t.Fatalf("gen-key: %v\n%s", err, out)
	}
	out, err := exec.Command(
		"gpg", "--list-keys", "--with-colons", "cipher-test@example.com",
	).Output()
	if err != nil {
		t.Fatalf("list-keys: %v", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.HasPrefix(line, "fpr:") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) >= 10 && parts[9] != "" {
			return parts[9]
		}
	}
	t.Fatal("no fingerprint in gpg --list-keys output")
	return ""
}
