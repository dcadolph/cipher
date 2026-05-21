// Package precommit detects unencrypted files that the project's
// .sops.yaml says should be encrypted. Use it from a git pre-commit
// hook (or any CI step) to fail builds before plaintext secrets land
// in version control.
package precommit

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/dcadolph/cipher"
	"github.com/dcadolph/cipher/sopsconfig"
)

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
	cfg *sopsconfig.Config
}

// NewChecker returns a Checker rooted at configPath. configPath may be
// a directory (in which case .sops.yaml is appended) or a file.
func NewChecker(configPath string) (*Checker, error) {
	cfg, err := sopsconfig.Load(configPath)
	if err != nil {
		return nil, fmt.Errorf("precommit: %w", err)
	}
	return &Checker{cfg: cfg}, nil
}

// NewCheckerForDir locates the nearest .sops.yaml at or above dir and
// returns a Checker backed by it.
func NewCheckerForDir(dir string) (*Checker, error) {
	cfg, err := sopsconfig.LoadFromDir(dir)
	if err != nil {
		return nil, fmt.Errorf("precommit: %w", err)
	}
	return &Checker{cfg: cfg}, nil
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
		data, err := gitStagedContent(p)
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

// gitStagedContent reads the staged blob for path.
func gitStagedContent(path string) ([]byte, error) {
	cmd := exec.Command("git", "show", ":"+path)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("precommit: git show %q: %w", path, err)
	}
	return out.Bytes(), nil
}
