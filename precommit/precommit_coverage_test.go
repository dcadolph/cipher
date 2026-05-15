package precommit_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/dcadolph/cipher"
	cipherage "github.com/dcadolph/cipher/age"
	"github.com/dcadolph/cipher/precommit"
	"github.com/dcadolph/cipher/sopsconfig"
)

// gitAvailable reports whether the git binary is on PATH. Tests that
// exercise CheckStaged skip when git is absent.
func gitAvailable(t *testing.T) bool {
	t.Helper()
	_, err := exec.LookPath("git")
	return err == nil
}

// runGit runs git in dir with the supplied args, failing the test on
// non-zero exit.
func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=test",
		"GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=test",
		"GIT_COMMITTER_EMAIL=test@example.com",
		"GIT_CONFIG_NOSYSTEM=1",
		"HOME="+t.TempDir(),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// TestNewCheckerMissingConfig verifies NewChecker errors when the
// config path does not exist.
func TestNewCheckerMissingConfig(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, err := precommit.NewChecker(filepath.Join(dir, "nope.yaml"))
	if err == nil {
		t.Fatal("err = nil, want missing-config error")
	}
	if !strings.Contains(err.Error(), "precommit") {
		t.Errorf("err = %v, want precommit prefix", err)
	}
}

// TestNewCheckerForDirNoConfig verifies NewCheckerForDir errors when no
// .sops.yaml is found.
func TestNewCheckerForDirNoConfig(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, err := precommit.NewCheckerForDir(dir)
	if err == nil {
		t.Fatal("err = nil, want missing-config error")
	}
}

// TestCheckPathsReadError verifies a missing file returns a read error.
func TestCheckPathsReadError(t *testing.T) {
	t.Parallel()
	dir, _, _ := writeFixture(t)
	checker, err := precommit.NewChecker(dir)
	if err != nil {
		t.Fatalf("NewChecker: %v", err)
	}
	missing := filepath.Join(dir, "secrets", "missing.yaml")
	_, err = checker.CheckPaths([]string{missing})
	if err == nil {
		t.Fatal("err = nil, want read error")
	}
	if !strings.Contains(err.Error(), "read") {
		t.Errorf("err = %v, want read substring", err)
	}
}

// TestCheckStagedReportsViolation drives CheckStaged through a real git
// repo: stage a plaintext file matched by the .sops.yaml rule and
// confirm the violation is reported.
func TestCheckStagedReportsViolation(t *testing.T) {
	if !gitAvailable(t) {
		t.Skip("git not available")
	}

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	recipient := id.Recipient().String()

	dir := t.TempDir()
	runGit(t, dir, "init", "-q", "-b", "main")

	cfgBody := fmt.Sprintf(
		"creation_rules:\n  - path_regex: secrets/.*\\.yaml$\n    age: %s\n",
		recipient,
	)
	cfgPath := filepath.Join(dir, sopsconfig.ConfigFileName)
	if err := os.WriteFile(cfgPath, []byte(cfgBody), 0o600); err != nil {
		t.Fatalf("write cfg: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "secrets"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	plain := filepath.Join(dir, "secrets", "leaky.yaml")
	if err := os.WriteFile(plain, []byte("foo: bar\n"), 0o600); err != nil {
		t.Fatalf("write plain: %v", err)
	}

	runGit(t, dir, "add", sopsconfig.ConfigFileName, "secrets/leaky.yaml")

	// Run the checker with cwd = repo so the git plumbing finds the index.
	prevWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(prevWD) })

	checker, err := precommit.NewCheckerForDir(dir)
	if err != nil {
		t.Fatalf("NewCheckerForDir: %v", err)
	}
	violations, err := checker.CheckStaged()
	if err != nil {
		t.Fatalf("CheckStaged: %v", err)
	}
	if len(violations) != 1 {
		t.Fatalf("violations = %d, want 1", len(violations))
	}
	if filepath.Base(violations[0].Path) != "leaky.yaml" {
		t.Errorf("violation path = %q, want leaky.yaml", violations[0].Path)
	}
}

// TestCheckStagedAllEncrypted verifies CheckStaged returns no violations
// when every staged file matching a rule is already encrypted.
func TestCheckStagedAllEncrypted(t *testing.T) {
	if !gitAvailable(t) {
		t.Skip("git not available")
	}

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	recipient := id.Recipient().String()

	dir := t.TempDir()
	runGit(t, dir, "init", "-q", "-b", "main")

	cfgBody := fmt.Sprintf(
		"creation_rules:\n  - path_regex: secrets/.*\\.yaml$\n    age: %s\n",
		recipient,
	)
	if err := os.WriteFile(filepath.Join(dir, sopsconfig.ConfigFileName),
		[]byte(cfgBody), 0o600); err != nil {
		t.Fatalf("cfg: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "secrets"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	enc := cipher.NewEncoder(cipherage.MustNewProvider(recipient))
	out, err := enc.Encode(context.Background(), "secrets/safe.yaml",
		[]byte("foo: bar\n"))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	encrypted := filepath.Join(dir, "secrets", "safe.yaml")
	if err := os.WriteFile(encrypted, out, 0o600); err != nil {
		t.Fatalf("write encrypted: %v", err)
	}

	runGit(t, dir, "add", sopsconfig.ConfigFileName, "secrets/safe.yaml")

	prevWD, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(prevWD) })

	checker, err := precommit.NewCheckerForDir(dir)
	if err != nil {
		t.Fatalf("NewCheckerForDir: %v", err)
	}
	violations, err := checker.CheckStaged()
	if err != nil {
		t.Fatalf("CheckStaged: %v", err)
	}
	if len(violations) != 0 {
		t.Errorf("violations = %d, want 0", len(violations))
	}
}

// TestCheckStagedEmpty verifies CheckStaged returns no violations and
// no error when the index has no staged paths.
func TestCheckStagedEmpty(t *testing.T) {
	if !gitAvailable(t) {
		t.Skip("git not available")
	}

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	recipient := id.Recipient().String()

	dir := t.TempDir()
	runGit(t, dir, "init", "-q", "-b", "main")

	cfgBody := fmt.Sprintf(
		"creation_rules:\n  - path_regex: secrets/.*\\.yaml$\n    age: %s\n",
		recipient,
	)
	if err := os.WriteFile(filepath.Join(dir, sopsconfig.ConfigFileName),
		[]byte(cfgBody), 0o600); err != nil {
		t.Fatalf("cfg: %v", err)
	}

	prevWD, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(prevWD) })

	checker, err := precommit.NewCheckerForDir(dir)
	if err != nil {
		t.Fatalf("NewCheckerForDir: %v", err)
	}
	violations, err := checker.CheckStaged()
	if err != nil {
		t.Fatalf("CheckStaged: %v", err)
	}
	if len(violations) != 0 {
		t.Errorf("violations = %d, want 0 on empty index", len(violations))
	}
}

// TestCheckStagedRejectsOversizedBlob verifies that staged blobs larger
// than WithMaxStagedBytes are rejected with ErrTooLarge rather than
// loaded into memory in full.
func TestCheckStagedRejectsOversizedBlob(t *testing.T) {
	if !gitAvailable(t) {
		t.Skip("git not available")
	}

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	recipient := id.Recipient().String()

	dir := t.TempDir()
	runGit(t, dir, "init", "-q", "-b", "main")

	cfgBody := fmt.Sprintf(
		"creation_rules:\n  - path_regex: secrets/.*\\.yaml$\n    age: %s\n",
		recipient,
	)
	if err := os.WriteFile(filepath.Join(dir, sopsconfig.ConfigFileName),
		[]byte(cfgBody), 0o600); err != nil {
		t.Fatalf("write cfg: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "secrets"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	plain := filepath.Join(dir, "secrets", "huge.yaml")
	if err := os.WriteFile(plain, []byte(strings.Repeat("a", 4096)), 0o600); err != nil {
		t.Fatalf("write plain: %v", err)
	}
	runGit(t, dir, "add", sopsconfig.ConfigFileName, "secrets/huge.yaml")

	prevWD, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(prevWD) })

	checker, err := precommit.NewCheckerForDir(dir, precommit.WithMaxStagedBytes(64))
	if err != nil {
		t.Fatalf("NewCheckerForDir: %v", err)
	}
	if _, err := checker.CheckStaged(); !errors.Is(err, precommit.ErrTooLarge) {
		t.Fatalf("err = %v, want errors.Is precommit.ErrTooLarge", err)
	}
}

// TestCheckStagedNotARepo verifies CheckStaged surfaces an error when
// the current directory is not inside a git repository.
func TestCheckStagedNotARepo(t *testing.T) {
	if !gitAvailable(t) {
		t.Skip("git not available")
	}
	dir, _, _ := writeFixture(t)

	prevWD, _ := os.Getwd()
	notRepo := t.TempDir()
	if err := os.Chdir(notRepo); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(prevWD) })

	checker, err := precommit.NewChecker(dir)
	if err != nil {
		t.Fatalf("NewChecker: %v", err)
	}
	if _, err := checker.CheckStaged(); err == nil {
		t.Fatal("err = nil, want git failure")
	}
}
