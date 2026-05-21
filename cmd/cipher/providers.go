package main

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/dcadolph/cipher"
	cipherage "github.com/dcadolph/cipher/age"
	"github.com/dcadolph/cipher/azkv"
	"github.com/dcadolph/cipher/gcpkms"
	"github.com/dcadolph/cipher/kms"
	"github.com/dcadolph/cipher/pgp"
	"github.com/dcadolph/cipher/sopsconfig"
	"github.com/dcadolph/cipher/vault"
)

// providerFlags holds the CLI flag values for sourcing key providers.
type providerFlags struct {
	age      string
	kms      string
	gcpkms   string
	vault    string
	azkv     string
	pgp      string
	config   string
	awsCtx   []string
	awsProf  string
}

// bind attaches the recipient flags to f. Repeated across encrypt/walk
// commands so users get consistent UX.
func (p *providerFlags) bind(f *pflag.FlagSet) {
	f.StringVar(&p.age, "age", "", "comma-separated age recipient public keys")
	f.StringVar(&p.kms, "kms", "", "comma-separated AWS KMS key ARNs")
	f.StringVar(&p.gcpkms, "gcp-kms", "", "comma-separated GCP KMS resource IDs")
	f.StringVar(&p.vault, "vault-uri", "", "comma-separated Vault Transit URIs")
	f.StringVar(&p.azkv, "azure-keyvault", "", "comma-separated Azure Key Vault URLs")
	f.StringVar(&p.pgp, "pgp", "", "comma-separated GPG fingerprints")
	f.StringVar(&p.config, "config", "", "path to .sops.yaml or directory containing it")
	f.StringSliceVar(&p.awsCtx, "kms-context", nil,
		"AWS KMS encryption context entries of form key=value (repeatable)")
	f.StringVar(&p.awsProf, "aws-profile", "",
		"AWS shared-credentials profile name for KMS calls")
}

// keyProvider builds a cipher.KeyProvider from the recipient flags.
// At least one of --age/--kms/--gcp-kms/--vault-uri/--azure-keyvault/--pgp
// must be supplied. --config is consumed by routerForPath in commands
// that support routing.
func (p *providerFlags) keyProvider() (cipher.KeyProvider, error) {
	var providers []cipher.KeyProvider
	if p.age != "" {
		providers = append(providers, cipherage.NewProviderFromCSV(p.age))
	}
	if p.kms != "" {
		ctx, err := parseAWSContext(p.awsCtx)
		if err != nil {
			return nil, err
		}
		opts := kms.ProviderOptions{EncryptionContext: ctx, Profile: p.awsProf}
		providers = append(providers, kms.NewProviderWith(opts, splitCSV(p.kms)...))
	}
	if p.gcpkms != "" {
		providers = append(providers, gcpkms.NewProviderFromCSV(p.gcpkms))
	}
	if p.vault != "" {
		providers = append(providers, vault.NewProviderFromCSV(p.vault))
	}
	if p.azkv != "" {
		providers = append(providers, azkv.NewProvider(splitCSV(p.azkv)...))
	}
	if p.pgp != "" {
		providers = append(providers, pgp.NewProviderFromCSV(p.pgp))
	}
	if len(providers) == 0 {
		return nil, errors.New(
			"at least one recipient flag is required: " +
				"--age, --kms, --gcp-kms, --vault-uri, --azure-keyvault, or --pgp",
		)
	}
	if len(providers) == 1 {
		return providers[0], nil
	}
	return cipher.MergeProviders(providers...), nil
}

// router builds a cipher.Router from --config, returning nil when no
// config is supplied (caller falls back to keyProvider).
func (p *providerFlags) router() (cipher.Router, error) {
	if p.config == "" {
		return nil, nil
	}
	cfg, err := sopsconfig.Load(p.config)
	if err != nil {
		return nil, err
	}
	return cfg.Router(nil), nil
}

// resolveEncoder builds an Encoder from the flags. When --config is set
// a routed encoder is returned; otherwise a direct encoder using the
// merged keyProvider.
func (p *providerFlags) resolveEncoder(_ *cobra.Command) (cipher.Encoder, error) {
	router, err := p.router()
	if err != nil {
		return nil, err
	}
	if router != nil {
		return cipher.NewRoutedEncoder(router, cipher.EncoderOptions{}), nil
	}
	kp, err := p.keyProvider()
	if err != nil {
		return nil, err
	}
	return cipher.NewEncoder(kp), nil
}

// parseAWSContext converts repeated `key=value` flag entries into the
// map[string]string sops's KMS context expects.
func parseAWSContext(in []string) (map[string]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(in))
	for _, entry := range in {
		k, v, ok := splitKV(entry)
		if !ok {
			return nil, fmt.Errorf("invalid --kms-context entry %q (expect key=value)", entry)
		}
		out[k] = v
	}
	return out, nil
}

// splitKV splits an entry of form "key=value" into (key, value, ok).
func splitKV(s string) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == '=' {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}

// splitCSV splits a comma-separated string into a slice with whitespace
// trimmed and empty entries dropped.
func splitCSV(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			tok := trimSpace(s[start:i])
			if tok != "" {
				out = append(out, tok)
			}
			start = i + 1
		}
	}
	return out
}

// trimSpace is a small helper to avoid importing strings here.
func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}
