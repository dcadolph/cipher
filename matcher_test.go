package cipher

import (
	"fmt"
	"regexp"
	"testing"
)

// TestMatchAll verifies MatchAll matches every input including empty.
func TestMatchAll(t *testing.T) {
	t.Parallel()
	m := MatchAll()
	for _, p := range []string{"", "a", "/dev/null", "foo.yaml"} {
		if !m.Match(p) {
			t.Errorf("MatchAll().Match(%q) = false, want true", p)
		}
	}
}

// TestMatchNone verifies MatchNone matches no input.
func TestMatchNone(t *testing.T) {
	t.Parallel()
	m := MatchNone()
	for _, p := range []string{"", "a", "/dev/null", "foo.yaml"} {
		if m.Match(p) {
			t.Errorf("MatchNone().Match(%q) = true, want false", p)
		}
	}
}

// TestMatchRegex covers regex-based matching including the nil-regex panic.
func TestMatchRegex(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Re   *regexp.Regexp
		In   string
		Want bool
	}{
		// Test 0: matches.
		{Re: regexp.MustCompile(`\.yaml$`), In: "a.yaml", Want: true},
		// Test 1: rejects.
		{Re: regexp.MustCompile(`\.yaml$`), In: "a.json", Want: false},
		// Test 2: anchor at start.
		{Re: regexp.MustCompile(`^/etc/`), In: "/etc/foo", Want: true},
	}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := MatchRegex(test.Re).Match(test.In)
			if got != test.Want {
				t.Errorf("got %v, want %v", got, test.Want)
			}
		})
	}

	t.Run("nil regex panics", func(t *testing.T) {
		t.Parallel()
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected panic on nil regex")
			}
		}()
		_ = MatchRegex(nil)
	})
}

// TestMatchExt covers extension matching including dot normalization
// and case-insensitive comparison.
func TestMatchExt(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Exts []string
		In   string
		Want bool
	}{
		// Test 0: leading dot honored.
		{Exts: []string{".yaml"}, In: "a.yaml", Want: true},
		// Test 1: leading dot inferred.
		{Exts: []string{"yaml"}, In: "a.yaml", Want: true},
		// Test 2: uppercase input.
		{Exts: []string{".yaml"}, In: "A.YAML", Want: true},
		// Test 3: multiple alternatives.
		{Exts: []string{"yaml", "json"}, In: "x.json", Want: true},
		// Test 4: miss.
		{Exts: []string{"yaml"}, In: "x.ini", Want: false},
		// Test 5: empty exts matches nothing.
		{Exts: nil, In: "x.yaml", Want: false},
	}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := MatchExt(test.Exts...).Match(test.In)
			if got != test.Want {
				t.Errorf("got %v, want %v", got, test.Want)
			}
		})
	}
}

// TestMatchGlob covers base-name glob matching and pattern validation.
func TestMatchGlob(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Pattern string
		In      string
		Want    bool
		WantErr bool
	}{
		// Test 0: simple star.
		{Pattern: "*.yaml", In: "/etc/secrets/foo.yaml", Want: true},
		// Test 1: miss.
		{Pattern: "*.yaml", In: "/etc/secrets/foo.json", Want: false},
		// Test 2: brackets.
		{Pattern: "[ab].yaml", In: "a.yaml", Want: true},
		// Test 3: invalid pattern.
		{Pattern: "[", In: "x", Want: false, WantErr: true},
	}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			m, err := MatchGlob(test.Pattern)
			if (err != nil) != test.WantErr {
				t.Fatalf("err = %v, wantErr = %v", err, test.WantErr)
			}
			if err != nil {
				return
			}
			got := m.Match(test.In)
			if got != test.Want {
				t.Errorf("got %v, want %v", got, test.Want)
			}
		})
	}
}

// TestMatchAnyOf verifies that MatchAnyOf is an OR over matchers and
// degenerates to MatchNone when empty.
func TestMatchAnyOf(t *testing.T) {
	t.Parallel()
	yaml := MatchExt("yaml")
	json := MatchExt("json")
	combo := MatchAnyOf(yaml, json)
	cases := map[string]bool{
		"a.yaml": true,
		"a.json": true,
		"a.ini":  false,
	}
	for in, want := range cases {
		if got := combo.Match(in); got != want {
			t.Errorf("MatchAnyOf(yaml, json).Match(%q) = %v, want %v", in, got, want)
		}
	}
	if MatchAnyOf().Match("anything") {
		t.Error("MatchAnyOf() should match nothing")
	}
}

// TestMatchAllOf verifies that MatchAllOf is an AND over matchers and
// degenerates to MatchAll when empty.
func TestMatchAllOf(t *testing.T) {
	t.Parallel()
	yaml := MatchExt("yaml")
	etc := MatchRegex(regexp.MustCompile(`^/etc/`))
	combo := MatchAllOf(yaml, etc)
	cases := map[string]bool{
		"/etc/a.yaml": true,
		"/tmp/a.yaml": false,
		"/etc/a.json": false,
	}
	for in, want := range cases {
		if got := combo.Match(in); got != want {
			t.Errorf("MatchAllOf(yaml, etc).Match(%q) = %v, want %v", in, got, want)
		}
	}
	if !MatchAllOf().Match("anything") {
		t.Error("MatchAllOf() should match everything")
	}
}

// TestMatchNot verifies inversion and nil panic.
func TestMatchNot(t *testing.T) {
	t.Parallel()
	m := MatchNot(MatchExt("yaml"))
	if m.Match("a.yaml") {
		t.Error("MatchNot(yaml).Match(a.yaml) = true, want false")
	}
	if !m.Match("a.json") {
		t.Error("MatchNot(yaml).Match(a.json) = false, want true")
	}
	t.Run("nil matcher panics", func(t *testing.T) {
		t.Parallel()
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected panic on nil matcher")
			}
		}()
		_ = MatchNot(nil)
	})
}

// TestFileMatcherFunc verifies that a plain function satisfies FileMatcher.
func TestFileMatcherFunc(t *testing.T) {
	t.Parallel()
	var m FileMatcher = FileMatcherFunc(func(p string) bool { return p == "x" })
	if !m.Match("x") || m.Match("y") {
		t.Error("FileMatcherFunc did not adapt as expected")
	}
}
