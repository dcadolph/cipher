package precommit_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/dcadolph/cipher"
	cipherage "github.com/dcadolph/cipher/age"
	"github.com/dcadolph/cipher/precommit"
	"github.com/dcadolph/cipher/sopsconfig"
)

// writeFixture lays down a temp dir with a .sops.yaml that selects
// "secrets/*.yaml" plus a plaintext file and an encrypted file.
// Returns the dir, the plain path, and the encrypted path.
func writeFixture(t *testing.T) (dir, plainPath, encryptedPath string) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	recipient := id.Recipient().String()
	dir = t.TempDir()
	body := fmt.Sprintf(
		"creation_rules:\n  - path_regex: secrets/.*\\.yaml$\n    age: %s\n",
		recipient,
	)
	cfgPath := filepath.Join(dir, sopsconfig.ConfigFileName)
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write sops config: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "secrets"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	plainPath = filepath.Join(dir, "secrets", "plain.yaml")
	if err := os.WriteFile(plainPath, []byte("foo: bar\n"), 0o600); err != nil {
		t.Fatalf("write plain: %v", err)
	}
	encryptedPath = filepath.Join(dir, "secrets", "enc.yaml")
	enc := cipher.NewEncoder(cipherage.MustNewProvider(recipient))
	out, err := enc.Encode(context.Background(), encryptedPath, []byte("foo: bar\n"))
	if err != nil {
		t.Fatalf("encode fixture: %v", err)
	}
	if err := os.WriteFile(encryptedPath, out, 0o600); err != nil {
		t.Fatalf("write encrypted: %v", err)
	}
	return dir, plainPath, encryptedPath
}

// TestCheckPathsFlagsPlaintextOnly verifies that CheckPaths reports the
// unencrypted file that matches a creation rule and does not flag the
// already-encrypted file.
func TestCheckPathsFlagsPlaintextOnly(t *testing.T) {
	t.Parallel()
	dir, plainPath, encryptedPath := writeFixture(t)
	checker, err := precommit.NewChecker(dir)
	if err != nil {
		t.Fatalf("NewChecker: %v", err)
	}
	violations, err := checker.CheckPaths([]string{plainPath, encryptedPath})
	if err != nil {
		t.Fatalf("CheckPaths: %v", err)
	}
	if len(violations) != 1 {
		t.Fatalf("violations = %d, want 1", len(violations))
	}
	if violations[0].Path != plainPath {
		t.Errorf("violation path = %q, want %q", violations[0].Path, plainPath)
	}
	if !strings.Contains(violations[0].Reason, "sops creation rule") {
		t.Errorf("reason = %q, missing context", violations[0].Reason)
	}
}

// TestCheckPathsIgnoresUnrelated verifies non-matching paths are not flagged.
func TestCheckPathsIgnoresUnrelated(t *testing.T) {
	t.Parallel()
	dir, _, _ := writeFixture(t)
	checker, err := precommit.NewChecker(dir)
	if err != nil {
		t.Fatalf("NewChecker: %v", err)
	}
	unrelated := filepath.Join(dir, "readme.md")
	if err := os.WriteFile(unrelated, []byte("hello\n"), 0o600); err != nil {
		t.Fatalf("write unrelated: %v", err)
	}
	violations, err := checker.CheckPaths([]string{unrelated})
	if err != nil {
		t.Fatalf("CheckPaths: %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("violations = %d, want 0", len(violations))
	}
}

// TestCheckBytes verifies the in-memory checker variant.
func TestCheckBytes(t *testing.T) {
	t.Parallel()
	dir, _, _ := writeFixture(t)
	checker, err := precommit.NewChecker(dir)
	if err != nil {
		t.Fatalf("NewChecker: %v", err)
	}
	items := []precommit.PathBytes{
		{Path: filepath.Join(dir, "secrets", "ghost.yaml"), Data: []byte("foo: bar\n")},
	}
	violations, err := checker.CheckBytes(items)
	if err != nil {
		t.Fatalf("CheckBytes: %v", err)
	}
	if len(violations) != 1 {
		t.Fatalf("violations = %d, want 1", len(violations))
	}
}

// TestNewCheckerForDirFindsConfig verifies the directory walker locates
// the config in a parent directory.
func TestNewCheckerForDirFindsConfig(t *testing.T) {
	t.Parallel()
	dir, _, _ := writeFixture(t)
	deep := filepath.Join(dir, "secrets")
	if _, err := precommit.NewCheckerForDir(deep); err != nil {
		t.Fatalf("NewCheckerForDir: %v", err)
	}
}

// TestViolationError verifies Violation implements error nicely.
func TestViolationError(t *testing.T) {
	t.Parallel()
	v := precommit.Violation{Path: "x.yaml", Reason: "bad"}
	if got := v.Error(); !strings.Contains(got, "x.yaml") || !strings.Contains(got, "bad") {
		t.Errorf("Error() = %q, missing context", got)
	}
}
