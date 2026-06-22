// Package strutil holds tiny helpers shared across cipher subpackages
// that would otherwise be reimplemented (or already were) in each
// provider package. Everything here is intentionally small: anything
// non-trivial belongs in a dedicated package.
package strutil

import "strings"

// TrimEmpty returns in with leading/trailing whitespace trimmed on
// each element and any resulting empty strings removed. It is the
// single source of truth for the trim-and-drop pattern used by every
// provider package when normalizing CSV recipient lists.
func TrimEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// SplitCSV splits s on commas and returns the trimmed, non-empty
// elements. Equivalent to TrimEmpty(strings.Split(s, ",")) but avoids
// the intermediate slice when no entries survive.
func SplitCSV(s string) []string {
	if s == "" {
		return nil
	}
	return TrimEmpty(strings.Split(s, ","))
}
