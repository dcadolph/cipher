package cipher_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/dcadolph/cipher"
)

// FuzzMatchExt feeds arbitrary extension lists and paths into the
// MatchExt builder. Any input that compiles must not panic when
// Match is called.
func FuzzMatchExt(f *testing.F) {
	f.Add("yaml,yml,json", "secrets/prod.yaml")
	f.Add("", "noext")
	f.Add(".YAML", "MIXED.yaml")
	f.Fuzz(func(t *testing.T, exts, path string) {
		parts := strings.Split(exts, ",")
		m := cipher.MatchExt(parts...)
		_ = m.Match(path)
	})
}

// FuzzMatchGlob feeds arbitrary glob patterns and paths. Patterns
// that fail to compile return an error and are skipped; patterns
// that compile must never panic on Match.
func FuzzMatchGlob(f *testing.F) {
	f.Add("**/*.yaml", "a/b/c.yaml")
	f.Add("secrets/*", "secrets/prod")
	f.Add("[", "anything")
	f.Fuzz(func(t *testing.T, pattern, path string) {
		m, err := cipher.MatchGlob(pattern)
		if err != nil {
			return
		}
		_ = m.Match(path)
	})
}

// FuzzMatchRegex feeds arbitrary regexes and paths. Patterns that
// fail to compile are skipped. Compiled patterns must never panic on
// Match.
func FuzzMatchRegex(f *testing.F) {
	f.Add(`\.yaml$`, "x.yaml")
	f.Add(`^secrets/`, "secrets/db")
	f.Add(`(?P<g>foo)`, "foo")
	f.Fuzz(func(t *testing.T, pattern, path string) {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return
		}
		m := cipher.MatchRegex(re)
		_ = m.Match(path)
	})
}
