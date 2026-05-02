package cipher

import (
	"context"
	"errors"
	"fmt"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/keyservice"
)

// ErrNoMatchingRule is returned by a Router when no rule matches.
var ErrNoMatchingRule = errors.New("no matching rule")

// Router returns the KeyProvider and partial EncoderOptions to use for
// a given file path. It is consulted on every Encode call by encoders
// built with NewRoutedEncoder.
type Router interface {
	// Resolve returns the KeyProvider and EncoderOptions for path.
	// Returns ErrNoMatchingRule when no rule matches.
	Resolve(path string) (KeyProvider, EncoderOptions, error)
}

// RouterFunc adapts a plain function to Router.
type RouterFunc func(path string) (KeyProvider, EncoderOptions, error)

// Resolve calls f with path.
func (f RouterFunc) Resolve(path string) (KeyProvider, EncoderOptions, error) {
	return f(path)
}

// Rule pairs a FileMatcher with the KeyProvider and EncoderOptions to
// apply when the matcher selects a path.
type Rule struct {
	// Match decides whether this rule applies to the given path.
	Match FileMatcher
	// Provider supplies key groups for matching paths.
	Provider KeyProvider
	// Options overrides EncoderOptions fields for matching paths.
	// Zero-valued fields inherit from the encoder's base options.
	Options EncoderOptions
}

// NewRouter returns a Router whose Resolve method scans rules in order
// and returns the first match. Panics if any rule has a nil Match or
// Provider.
func NewRouter(rules ...Rule) Router {
	for i, r := range rules {
		if r.Match == nil {
			panic(fmt.Sprintf("cipher: NewRouter: rule %d has nil Match", i))
		}
		if r.Provider == nil {
			panic(fmt.Sprintf("cipher: NewRouter: rule %d has nil Provider", i))
		}
	}
	frozen := append([]Rule(nil), rules...)
	return RouterFunc(func(path string) (KeyProvider, EncoderOptions, error) {
		for _, r := range frozen {
			if r.Match.Match(path) {
				return r.Provider, r.Options, nil
			}
		}
		return nil, EncoderOptions{}, fmt.Errorf("%w: %q", ErrNoMatchingRule, path)
	})
}

// NewRoutedEncoder returns an Encoder that consults router on every
// Encode call. Fields set on the matched rule's EncoderOptions override
// the same fields in base; zero-valued fields inherit base.
// Panics if router is nil.
func NewRoutedEncoder(router Router, base EncoderOptions) Encoder {
	if router == nil {
		panic("cipher: NewRoutedEncoder: router required")
	}
	return EncoderFunc(func(ctx context.Context, path string, data []byte) ([]byte, error) {
		kp, ruleOpts, err := router.Resolve(path)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrEncode, err)
		}
		return NewEncoderWith(kp, mergeEncoderOptions(base, ruleOpts)).
			Encode(ctx, path, data)
	})
}

// NewShamirRule returns a Rule that maps match to a multi-group
// KeyProvider with the supplied Shamir threshold. Each provider
// contributes its groups as separate key groups in the resulting rule.
// At least threshold groups must successfully decrypt to recover the
// data key.
//
// Panics if match or any provider is nil, or if threshold is non-positive.
func NewShamirRule(match FileMatcher, threshold int, providers ...KeyProvider) Rule {
	if match == nil {
		panic("cipher: NewShamirRule: match required")
	}
	if threshold <= 0 {
		panic("cipher: NewShamirRule: threshold must be positive")
	}
	for i, p := range providers {
		if p == nil {
			panic(fmt.Sprintf("cipher: NewShamirRule: provider %d is nil", i))
		}
	}
	if len(providers) < threshold {
		panic(fmt.Sprintf(
			"cipher: NewShamirRule: %d providers but threshold %d",
			len(providers), threshold,
		))
	}
	return Rule{
		Match:    match,
		Provider: ChainKeyProviders(providers...),
		Options:  EncoderOptions{ShamirThreshold: threshold},
	}
}

// MergeProviders returns a KeyProvider whose single group contains
// every key from every group of every supplied provider. Useful when
// a rule needs to encrypt the data key with mixed backends
// (e.g. one age recipient AND one KMS ARN in the same group).
//
// Empty members: any provider that returns no groups (or only empty
// groups) contributes no keys and does not produce a placeholder
// group in the output. The result is always either nil (when every
// member contributed nothing) or a single non-empty group. Callers
// that need to preserve group boundaries should use
// ChainKeyProviders instead, which keeps each member's groups intact
// and may emit empty groups when a member returns an empty group.
func MergeProviders(providers ...KeyProvider) KeyProvider {
	return KeyProviderFunc(func(ctx context.Context) ([]sops.KeyGroup, error) {
		var merged sops.KeyGroup
		for _, p := range providers {
			groups, err := p.KeyGroups(ctx)
			if err != nil {
				return nil, err
			}
			for _, g := range groups {
				merged = append(merged, g...)
			}
		}
		if len(merged) == 0 {
			return nil, nil
		}
		return []sops.KeyGroup{merged}, nil
	})
}

// mergeEncoderOptions returns the result of overlaying rule fields onto
// base. Non-zero/non-empty fields in rule win, zero fields fall through
// to base.
//
// Boolean fields (currently MACOnlyEncrypted) follow the same
// zero-is-inherit rule. A rule can enable MACOnlyEncrypted on top of a
// base that did not set it, but cannot disable a base that did. If
// per-rule disabling is needed, set MACOnlyEncrypted to false at the
// Encoder level and enable it only on the rules that want it.
func mergeEncoderOptions(base, rule EncoderOptions) EncoderOptions {
	out := base
	if rule.Format != 0 {
		out.Format = rule.Format
	}
	if rule.EncryptedRegex != "" {
		out.EncryptedRegex = rule.EncryptedRegex
	}
	if rule.UnencryptedRegex != "" {
		out.UnencryptedRegex = rule.UnencryptedRegex
	}
	if rule.EncryptedSuffix != "" {
		out.EncryptedSuffix = rule.EncryptedSuffix
	}
	if rule.UnencryptedSuffix != "" {
		out.UnencryptedSuffix = rule.UnencryptedSuffix
	}
	if rule.MACOnlyEncrypted {
		out.MACOnlyEncrypted = rule.MACOnlyEncrypted
	}
	if rule.ShamirThreshold != 0 {
		out.ShamirThreshold = rule.ShamirThreshold
	}
	if len(rule.KeyServices) > 0 {
		out.KeyServices = appendUniqueKS(base.KeyServices, rule.KeyServices)
	}
	if rule.Cipher != nil {
		out.Cipher = rule.Cipher
	}
	return out
}

// appendUniqueKS appends entries from b to a, preserving order and
// dropping exact duplicates (pointer equality).
func appendUniqueKS(
	a, b []keyservice.KeyServiceClient,
) []keyservice.KeyServiceClient {
	out := append([]keyservice.KeyServiceClient(nil), a...)
	for _, x := range b {
		dup := false
		for _, y := range out {
			if x == y {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, x)
		}
	}
	return out
}
