// Package precommit detects unencrypted files that the project's
// .sops.yaml says should be encrypted.
//
// Use it from a git pre-commit hook (or any CI step) to fail builds
// before plaintext secrets land in version control. The CLI verb
// `cipher precommit` runs [Checker.CheckStaged] against the current
// repository.
//
// # What it checks
//
// For each candidate path, the Checker:
//
//   - Asks the project's .sops.yaml whether any creation rule matches.
//   - If a rule matches, verifies the file's bytes parse as a
//     sops-encrypted file via [cipher.IsEncrypted].
//   - Returns a [Violation] for any file that matches a rule but is
//     not sops-encrypted.
//
// # Three entry points
//
//   - [Checker.CheckStaged] inspects the staged blobs of every file in
//     `git diff --cached`. This is what `cipher precommit` calls.
//   - [Checker.CheckPaths] inspects files on disk.
//   - [Checker.CheckBytes] inspects in-memory (path, bytes) pairs,
//     useful for tests and custom hosts that already have the bytes.
//
// # Quick start
//
//	import "github.com/dcadolph/cipher/precommit"
//
//	checker, err := precommit.NewCheckerForDir(".")
//	if err != nil { /* ... */ }
//
//	violations, err := checker.CheckStaged()
//	if err != nil { /* ... */ }
//	if len(violations) > 0 {
//	    for _, v := range violations {
//	        fmt.Fprintln(os.Stderr, v.Error())
//	    }
//	    os.Exit(1)
//	}
package precommit

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/dcadolph/cipher"
	"github.com/dcadolph/cipher/sopsconfig"
)

// DefaultMaxStagedBytes caps the staged blob read per file. A staged
// blob larger than this is rejected with ErrTooLarge rather than
// loaded into memory. Override with WithMaxStagedBytes.
const DefaultMaxStagedBytes int64 = 64 << 20

// ErrTooLarge is returned when a staged blob exceeds the configured
// MaxStagedBytes limit. Callers can match with errors.Is.
var ErrTooLarge = errors.New("precommit: staged blob exceeds size limit")

// Violation is a single offending file: it matches a creation rule in
// the .sops.yaml but is not sops-encrypted.
type Violation struct {
	// Path is the offending file path.
	Path string
	// Reason is a short human-readable explanation.
	Reason string
}

// Error returns a Violation as an error string.
func (v Violation) Error() string {
	return fmt.Sprintf("%s: %s", v.Path, v.Reason)
}

// Checker scans files against a single resolved sops config.
type Checker struct {
	cfg            *sopsconfig.Config
	maxStagedBytes int64
}

// Option tunes a Checker.
type Option func(*Checker)

// WithMaxStagedBytes overrides DefaultMaxStagedBytes for CheckStaged.
// A value of zero disables the cap. Negative values are clamped to zero.
func WithMaxStagedBytes(n int64) Option {
	return func(c *Checker) {
		if n < 0 {
			n = 0
		}
		c.maxStagedBytes = n
	}
}

// NewChecker returns a Checker rooted at configPath. configPath may be
// a directory (in which case .sops.yaml is appended) or a file.
func NewChecker(configPath string, opts ...Option) (*Checker, error) {
	cfg, err := sopsconfig.Load(configPath)
	if err != nil {
		return nil, fmt.Errorf("precommit: %w", err)
	}
	return newChecker(cfg, opts), nil
}

// NewCheckerForDir locates the nearest .sops.yaml at or above dir and
// returns a Checker backed by it.
func NewCheckerForDir(dir string, opts ...Option) (*Checker, error) {
	cfg, err := sopsconfig.LoadFromDir(dir)
	if err != nil {
		return nil, fmt.Errorf("precommit: %w", err)
	}
	return newChecker(cfg, opts), nil
}

// newChecker builds a Checker with options applied and defaults filled in.
func newChecker(cfg *sopsconfig.Config, opts []Option) *Checker {
	c := &Checker{cfg: cfg, maxStagedBytes: DefaultMaxStagedBytes}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// CheckPaths scans the supplied filesystem paths against the config
// and returns any that match a creation rule but are not encrypted.
func (c *Checker) CheckPaths(paths []string) ([]Violation, error) {
	var violations []Violation
	for _, p := range paths {
		v, err := c.checkPath(p, nil)
		if err != nil {
			return nil, err
		}
		if v != nil {
			violations = append(violations, *v)
		}
	}
	return violations, nil
}

// CheckBytes scans the supplied (path, bytes) pairs against the config.
// Use this when the file contents on disk differ from what is being
// considered (for example, the git-staged blob).
func (c *Checker) CheckBytes(items []PathBytes) ([]Violation, error) {
	var violations []Violation
	for _, it := range items {
		v, err := c.checkPath(it.Path, it.Data)
		if err != nil {
			return nil, err
		}
		if v != nil {
			violations = append(violations, *v)
		}
	}
	return violations, nil
}

// CheckStaged scans the files currently staged in the git repository
// containing the working directory. Each file's staged blob (not the
// working-tree copy) is inspected.
func (c *Checker) CheckStaged() ([]Violation, error) {
	paths, err := gitStagedPaths()
	if err != nil {
		return nil, err
	}
	items := make([]PathBytes, 0, len(paths))
	for _, p := range paths {
		data, err := gitStagedContent(p, c.maxStagedBytes)
		if err != nil {
			return nil, err
		}
		items = append(items, PathBytes{Path: p, Data: data})
	}
	return c.CheckBytes(items)
}

// PathBytes pairs a file path with its byte contents for CheckBytes.
type PathBytes struct {
	// Path is the file's name, used for matcher and format inference.
	Path string
	// Data is the file content to inspect.
	Data []byte
}

// checkPath returns a Violation if path matches a creation rule but is
// not sops-encrypted. data is the file content; if nil, it is loaded
// from disk using os.ReadFile.
func (c *Checker) checkPath(path string, data []byte) (*Violation, error) {
	matched, err := c.cfg.MatchesAnyRule(path, nil)
	if err != nil {
		return nil, fmt.Errorf("precommit: match %q: %w", path, err)
	}
	if !matched {
		return nil, nil
	}
	if data == nil {
		data, err = os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("precommit: read %q: %w", path, err)
		}
	}
	if cipher.IsEncryptedPath(path, data) {
		return nil, nil
	}
	return &Violation{
		Path:   path,
		Reason: "matches sops creation rule but is not sops-encrypted",
	}, nil
}

// gitStagedPaths shells out to git to list paths staged for commit.
func gitStagedPaths() ([]string, error) {
	cmd := exec.Command("git", "diff", "--cached", "--name-only", "--diff-filter=ACMR")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("precommit: git diff --cached: %w: %s", err, out.String())
	}
	raw := strings.TrimSpace(out.String())
	if raw == "" {
		return nil, nil
	}
	return strings.Split(raw, "\n"), nil
}

// gitStagedContent reads the staged blob for path. If maxBytes > 0,
// returns ErrTooLarge when the blob would exceed the cap, without
// loading the entire blob into memory.
func gitStagedContent(path string, maxBytes int64) ([]byte, error) {
	cmd := exec.Command("git", "show", ":"+path)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("precommit: git show %q: stdout pipe: %w", path, err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("precommit: git show %q: start: %w", path, err)
	}

	reader := io.Reader(stdout)
	if maxBytes > 0 {
		reader = io.LimitReader(stdout, maxBytes+1)
	}
	data, readErr := io.ReadAll(reader)
	if maxBytes > 0 && int64(len(data)) > maxBytes {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("precommit: %q: %w (limit %d bytes)", path, ErrTooLarge, maxBytes)
	}
	if waitErr := cmd.Wait(); waitErr != nil {
		return nil, fmt.Errorf("precommit: git show %q: %w: %s", path, waitErr, stderr.String())
	}
	if readErr != nil {
		return nil, fmt.Errorf("precommit: git show %q: read: %w", path, readErr)
	}
	return data, nil
}
