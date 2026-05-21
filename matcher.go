package cipher

import (
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// FileMatcher decides whether a path should be processed by a walker.
type FileMatcher interface {
	// Match reports whether path is selected by this matcher.
	Match(path string) bool
}

// FileMatcherFunc adapts a plain function to FileMatcher.
type FileMatcherFunc func(path string) bool

// Match calls f with the given path.
func (f FileMatcherFunc) Match(p string) bool { return f(p) }

// MatchAll returns a matcher that selects every path.
func MatchAll() FileMatcher {
	return FileMatcherFunc(func(string) bool { return true })
}

// MatchNone returns a matcher that selects no path.
func MatchNone() FileMatcher {
	return FileMatcherFunc(func(string) bool { return false })
}

// MatchRegex returns a matcher that selects paths matching re.
// Panics if re is nil.
func MatchRegex(re *regexp.Regexp) FileMatcher {
	if re == nil {
		panic("cipher: MatchRegex: regex required")
	}
	return FileMatcherFunc(func(p string) bool { return re.MatchString(p) })
}

// MatchExt returns a matcher that selects paths with any of the given
// file extensions. Extensions may be supplied with or without a leading
// dot and are compared case-insensitively.
func MatchExt(exts ...string) FileMatcher {
	if len(exts) == 0 {
		return MatchNone()
	}
	norm := make([]string, len(exts))
	for i, e := range exts {
		if !strings.HasPrefix(e, ".") {
			e = "." + e
		}
		norm[i] = strings.ToLower(e)
	}
	return FileMatcherFunc(func(p string) bool {
		ext := strings.ToLower(filepath.Ext(p))
		for _, e := range norm {
			if ext == e {
				return true
			}
		}
		return false
	})
}

// MatchGlob returns a matcher that selects paths whose base name matches
// pattern using path.Match. Returns an error if pattern is invalid.
func MatchGlob(pattern string) (FileMatcher, error) {
	if _, err := path.Match(pattern, "x"); err != nil {
		return nil, fmt.Errorf("cipher: MatchGlob: invalid pattern %q: %w", pattern, err)
	}
	return FileMatcherFunc(func(p string) bool {
		ok, _ := path.Match(pattern, filepath.Base(p))
		return ok
	}), nil
}

// MatchAnyOf returns a matcher that selects paths matched by any of the
// supplied matchers. With no matchers, returns MatchNone.
func MatchAnyOf(matchers ...FileMatcher) FileMatcher {
	if len(matchers) == 0 {
		return MatchNone()
	}
	return FileMatcherFunc(func(p string) bool {
		for _, m := range matchers {
			if m.Match(p) {
				return true
			}
		}
		return false
	})
}

// MatchAllOf returns a matcher that selects paths matched by every
// supplied matcher. With no matchers, returns MatchAll.
func MatchAllOf(matchers ...FileMatcher) FileMatcher {
	if len(matchers) == 0 {
		return MatchAll()
	}
	return FileMatcherFunc(func(p string) bool {
		for _, m := range matchers {
			if !m.Match(p) {
				return false
			}
		}
		return true
	})
}

// MatchNot returns a matcher that inverts m.
func MatchNot(m FileMatcher) FileMatcher {
	if m == nil {
		panic("cipher: MatchNot: matcher required")
	}
	return FileMatcherFunc(func(p string) bool { return !m.Match(p) })
}
