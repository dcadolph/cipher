// Package sopsconfig parses a sops .sops.yaml configuration file and
// exposes it as a cipher.Router.
//
// The router consults sops's own config loader on every Resolve call,
// so the project's existing .sops.yaml rules drive cipher encryption
// decisions. Matching semantics are identical to the sops CLI's
// creation_rules: each rule has a path_regex and a set of recipients
// (key_groups), and the first matching rule wins.
//
// # Locating .sops.yaml
//
// Use [Load] to point at an explicit file or directory. Use
// [LoadFromDir] to walk upward from a starting directory until a
// .sops.yaml is found, the same way the sops CLI does.
//
// # Quick start
//
//	import (
//	    "github.com/dcadolph/cipher"
//	    "github.com/dcadolph/cipher/sopsconfig"
//	)
//
//	cfg, err := sopsconfig.LoadFromDir(".")
//	if err != nil { /* ... */ }
//
//	router := cfg.Router(nil) // nil = no KMS encryption context
//	enc := cipher.NewRoutedEncoder(router, cipher.EncoderOptions{})
//
//	ciphertext, err := enc.Encode(ctx, "secrets/prod/db.yaml", plain)
//
// Non-matching paths cause Encode to return an error wrapping
// [cipher.ErrNoMatchingRule].
//
// [MatchesAnyRule] is a convenience for code (such as a pre-commit
// hook) that wants to ask whether a path would be encrypted without
// actually building an encoder.
package sopsconfig

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	sopsconfig "github.com/getsops/sops/v3/config"

	"github.com/dcadolph/cipher"
)

// ConfigFileName is the default sops configuration file name.
const ConfigFileName = ".sops.yaml"

// Config is a resolved reference to a .sops.yaml file. Use Load or
// LoadFromDir to obtain one, then call Router to wire it into an
// encoder.
type Config struct {
	// Path is the resolved absolute path to the .sops.yaml file.
	Path string
}

// Load returns a Config rooted at the file at path. If path is a
// directory, ConfigFileName is appended.
func Load(path string) (*Config, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("sopsconfig: abs %q: %w", path, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("sopsconfig: stat %q: %w", abs, err)
	}
	if info.IsDir() {
		abs = filepath.Join(abs, ConfigFileName)
		if _, err := os.Stat(abs); err != nil {
			return nil, fmt.Errorf("sopsconfig: stat %q: %w", abs, err)
		}
	}
	return &Config{Path: abs}, nil
}

// LoadFromDir locates the nearest .sops.yaml starting at dir and walking
// up to the filesystem root. Returns os.ErrNotExist if no config is found.
func LoadFromDir(dir string) (*Config, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("sopsconfig: abs %q: %w", dir, err)
	}
	cur := abs
	for {
		candidate := filepath.Join(cur, ConfigFileName)
		if _, err := os.Stat(candidate); err == nil {
			return &Config{Path: candidate}, nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return nil, fmt.Errorf("sopsconfig: no %s found at or above %q: %w",
				ConfigFileName, abs, os.ErrNotExist)
		}
		cur = parent
	}
}

// Router returns a cipher.Router that consults the underlying sops
// config on every Resolve call. kmsContext is forwarded to sops as the
// KMS encryption context (use nil for none).
func (c *Config) Router(kmsContext map[string]string) cipher.Router {
	ptrCtx := toPtrMap(kmsContext)
	confPath := c.Path
	return cipher.RouterFunc(func(path string) (cipher.KeyProvider, cipher.EncoderOptions, error) {
		cfg, err := sopsconfig.LoadCreationRuleForFile(confPath, path, ptrCtx)
		if err != nil {
			if isNoMatchErr(err) {
				return nil, cipher.EncoderOptions{},
					fmt.Errorf("%w: %q", cipher.ErrNoMatchingRule, path)
			}
			return nil, cipher.EncoderOptions{},
				fmt.Errorf("sopsconfig: load rule for %q: %w", path, err)
		}
		if cfg == nil || len(cfg.KeyGroups) == 0 {
			return nil, cipher.EncoderOptions{},
				fmt.Errorf("%w: %q", cipher.ErrNoMatchingRule, path)
		}
		kp := cipher.StaticKeyProvider(cfg.KeyGroups...)
		opts := cipher.EncoderOptions{
			EncryptedRegex:    cfg.EncryptedRegex,
			UnencryptedRegex:  cfg.UnencryptedRegex,
			EncryptedSuffix:   cfg.EncryptedSuffix,
			UnencryptedSuffix: cfg.UnencryptedSuffix,
			MAC:               macModeFromBool(cfg.MACOnlyEncrypted),
			ShamirThreshold:   cfg.ShamirThreshold,
		}
		return kp, opts, nil
	})
}

// MatchesAnyRule reports whether path matches any creation rule in the
// underlying .sops.yaml.
func (c *Config) MatchesAnyRule(path string, kmsContext map[string]string) (bool, error) {
	_, _, err := c.Router(kmsContext).Resolve(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, cipher.ErrNoMatchingRule) {
		return false, nil
	}
	return false, err
}

// isNoMatchErr translates sops's untyped "no matching creation rules"
// error into a signal we can wrap with cipher.ErrNoMatchingRule.
func isNoMatchErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "no matching creation rules")
}

// macModeFromBool maps the legacy bool field from .sops.yaml to the
// MACMode tri-state. A .sops.yaml rule can only set true (encrypted
// leaves only) or false (default sops MAC over all leaves); rules
// cannot express MACInherit because the config file format has no
// such notion.
func macModeFromBool(macOnlyEncrypted bool) cipher.MACMode {
	if macOnlyEncrypted {
		return cipher.MACOnEncrypted
	}
	return cipher.MACOnAll
}

// toPtrMap converts a string map to the *string map sops requires for
// KMS encryption context.
func toPtrMap(in map[string]string) map[string]*string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]*string, len(in))
	for k, v := range in {
		out[k] = &v
	}
	return out
}
