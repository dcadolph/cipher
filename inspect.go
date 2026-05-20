package cipher

import (
	"errors"
	"fmt"

	"github.com/dcadolph/cipher/internal/sopsx"
)

// Info summarizes the metadata of a sops-encrypted file without
// requiring decryption.
type Info = sopsx.Info

// RecipientInfo describes a single recipient recorded in a file's metadata.
type RecipientInfo = sopsx.RecipientInfo

// Inspect parses data as a sops-encrypted file and returns its metadata
// without decrypting the payload. Returns ErrNotEncrypted if the data
// does not parse as a sops file with metadata.
func Inspect(data []byte, format Format) (*Info, error) {
	info, err := sopsx.Inspect(data, format)
	if errors.Is(err, sopsx.ErrNotEncrypted) {
		return nil, ErrNotEncrypted
	}
	if err != nil {
		return nil, err
	}
	return info, nil
}

// InspectPath is Inspect with format inferred from path.
func InspectPath(path string, data []byte) (*Info, error) {
	return Inspect(data, FormatForPath(path))
}

// RecipientDiff is the result of DiffRecipients.
type RecipientDiff struct {
	// Added are recipients present in `after` but not `before`,
	// reported as "<type>:<identifier>" strings.
	Added []string
	// Removed are recipients present in `before` but not `after`.
	Removed []string
}

// Empty reports whether the diff has no additions or removals.
func (d RecipientDiff) Empty() bool {
	return len(d.Added) == 0 && len(d.Removed) == 0
}

// DiffRecipients compares the recipients recorded in two sops-encrypted
// files (presumably two versions of the same secret) and returns which
// recipients were added or removed. Useful in code review of secret
// rotations.
func DiffRecipients(
	beforeFmt Format, before []byte,
	afterFmt Format, after []byte,
) (RecipientDiff, error) {
	a, err := Inspect(before, beforeFmt)
	if err != nil {
		return RecipientDiff{}, fmt.Errorf("inspect before: %w", err)
	}
	b, err := Inspect(after, afterFmt)
	if err != nil {
		return RecipientDiff{}, fmt.Errorf("inspect after: %w", err)
	}
	beforeSet := recipientSet(a)
	afterSet := recipientSet(b)

	var diff RecipientDiff
	for id := range afterSet {
		if _, ok := beforeSet[id]; !ok {
			diff.Added = append(diff.Added, id)
		}
	}
	for id := range beforeSet {
		if _, ok := afterSet[id]; !ok {
			diff.Removed = append(diff.Removed, id)
		}
	}
	sortStrings(diff.Added)
	sortStrings(diff.Removed)
	return diff, nil
}

// DiffRecipientsPath is DiffRecipients with format inferred from path.
// Both files are expected to have the same format.
func DiffRecipientsPath(path string, before, after []byte) (RecipientDiff, error) {
	f := FormatForPath(path)
	return DiffRecipients(f, before, f, after)
}

// recipientSet returns the set of "<type>:<identifier>" strings across
// every key group in info.
func recipientSet(info *Info) map[string]struct{} {
	out := make(map[string]struct{})
	for _, g := range info.Groups {
		for _, r := range g {
			out[r.Type+":"+r.Identifier] = struct{}{}
		}
	}
	return out
}

// sortStrings sorts ss in place using stdlib sort.Strings via a tiny
// adapter to avoid the import in this file.
func sortStrings(ss []string) {
	// Local insertion sort: lists are typically tiny (handful of recipients).
	for i := 1; i < len(ss); i++ {
		for j := i; j > 0 && ss[j-1] > ss[j]; j-- {
			ss[j-1], ss[j] = ss[j], ss[j-1]
		}
	}
}
