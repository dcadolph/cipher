package sopsconfig_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/dcadolph/cipher"
	"github.com/dcadolph/cipher/sopsconfig"
)

// writeFixture builds a temp directory containing a .sops.yaml with
// three creation rules backed by fresh age recipients and returns the
// directory plus the first rule's encrypted_regex for assertions.
func writeFixture(t *testing.T) (dir, encryptedRegex string) {
	t.Helper()
	r1, _ := freshRecipient(t), freshRecipient(t)
	r3 := freshRecipient(t)

	dir = t.TempDir()
	encryptedRegex = "^(data|stringData)$"
	body := fmt.Sprintf(`creation_rules:
  - path_regex: secrets/prod/.*\.yaml$
    age: %s
    encrypted_regex: %s
  - path_regex: secrets/dev/.*
    age: %s
  - path_regex: .*\.json$
    age: %s
`, r1, encryptedRegex, r1, r3)
	cfgPath := filepath.Join(dir, sopsconfig.ConfigFileName)
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write sops config: %v", err)
	}
	return dir, encryptedRegex
}

// TestLoadByDir verifies Load accepts a directory and appends the config name.
func TestLoadByDir(t *testing.T) {
	t.Parallel()
	dir, _ := writeFixture(t)
	cfg, err := sopsconfig.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := filepath.Join(dir, sopsconfig.ConfigFileName)
	if cfg.Path != want {
		t.Errorf("Path = %q, want %q", cfg.Path, want)
	}
}

// TestLoadFromDirWalksUp verifies that LoadFromDir finds the config in
// a deeper subdirectory.
func TestLoadFromDirWalksUp(t *testing.T) {
	t.Parallel()
	dir, _ := writeFixture(t)
	deep := filepath.Join(dir, "secrets", "prod")
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	cfg, err := sopsconfig.LoadFromDir(deep)
	if err != nil {
		t.Fatalf("LoadFromDir: %v", err)
	}
	want := filepath.Join(dir, sopsconfig.ConfigFileName)
	if cfg.Path != want {
		t.Errorf("Path = %q, want %q", cfg.Path, want)
	}
}

// TestLoadFromDirMissing verifies the not-found error path wraps
// os.ErrNotExist.
func TestLoadFromDirMissing(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	_, err := sopsconfig.LoadFromDir(tmp)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v, want errors.Is os.ErrNotExist", err)
	}
}

// TestRouterResolvesByPathRegex verifies that the router picks the
// correct rule for a given path and surfaces ErrNoMatchingRule when
// no rule matches.
func TestRouterResolvesByPathRegex(t *testing.T) {
	t.Parallel()
	dir, encryptedRegex := writeFixture(t)
	cfg, err := sopsconfig.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	router := cfg.Router(nil)

	tests := []struct {
		Path                 string
		WantMatch            bool
		WantEncryptedRegex   string
	}{
		// Test 0: prod yaml matches first rule (encrypted_regex set).
		{
			Path:               filepath.Join(dir, "secrets/prod/api.yaml"),
			WantMatch:          true,
			WantEncryptedRegex: encryptedRegex,
		},
		// Test 1: dev path matches second rule (no encrypted_regex).
		{Path: filepath.Join(dir, "secrets/dev/api.yaml"), WantMatch: true},
		// Test 2: any json matches third rule.
		{Path: filepath.Join(dir, "other/data.json"), WantMatch: true},
		// Test 3: unrelated path matches nothing.
		{Path: filepath.Join(dir, "unrelated.txt"), WantMatch: false},
	}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			kp, opts, err := router.Resolve(test.Path)
			if test.WantMatch {
				if err != nil {
					t.Fatalf("Resolve: %v", err)
				}
				if kp == nil {
					t.Fatalf("nil KeyProvider")
				}
				groups, gErr := kp.KeyGroups(context.Background())
				if gErr != nil {
					t.Fatalf("KeyGroups: %v", gErr)
				}
				if len(groups) == 0 {
					t.Fatalf("no groups returned")
				}
				if test.WantEncryptedRegex != "" && opts.EncryptedRegex != test.WantEncryptedRegex {
					t.Errorf("EncryptedRegex = %q, want %q", opts.EncryptedRegex, test.WantEncryptedRegex)
				}
			} else {
				if !errors.Is(err, cipher.ErrNoMatchingRule) {
					t.Errorf("err = %v, want errors.Is ErrNoMatchingRule", err)
				}
			}
		})
	}
}

// TestMatchesAnyRule verifies MatchesAnyRule wraps Resolve cleanly.
func TestMatchesAnyRule(t *testing.T) {
	t.Parallel()
	dir, _ := writeFixture(t)
	cfg, err := sopsconfig.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	matched, err := cfg.MatchesAnyRule(filepath.Join(dir, "secrets/prod/api.yaml"), nil)
	if err != nil {
		t.Fatalf("MatchesAnyRule: %v", err)
	}
	if !matched {
		t.Error("expected match for prod yaml")
	}
	matched, err = cfg.MatchesAnyRule(filepath.Join(dir, "unrelated.txt"), nil)
	if err != nil {
		t.Fatalf("MatchesAnyRule: %v", err)
	}
	if matched {
		t.Error("expected no match for unrelated path")
	}
}

// freshRecipient returns the public recipient string for a freshly
// generated age identity.
func freshRecipient(t *testing.T) string {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	r := id.Recipient().String()
	if !strings.HasPrefix(r, "age1") {
		t.Fatalf("unexpected recipient form: %q", r)
	}
	return r
}
