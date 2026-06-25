package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/dcadolph/cipher"
	cipherage "github.com/dcadolph/cipher/age"
	"github.com/dcadolph/cipher/azkv"
	"github.com/dcadolph/cipher/gcpkms"
	"github.com/dcadolph/cipher/internal/strutil"
	"github.com/dcadolph/cipher/kms"
	"github.com/dcadolph/cipher/pgp"
	"github.com/dcadolph/cipher/sopsconfig"
	"github.com/dcadolph/cipher/vault"
)

// providerFlags holds the CLI flag values for sourcing key providers
// and tuning encoder behavior.
type providerFlags struct {
	age     string
	kms     string
	gcpkms  string
	vault   string
	azkv    string
	pgp     string
	config  string
	awsCtx  []string
	awsProf string

	encryptedRegex    string
	unencryptedRegex  string
	encryptedSuffix   string
	unencryptedSuffix string
	macOnlyEncrypted  bool
	shamirThreshold   int
}

// bind attaches the recipient and encoder-tuning flags to f. Repeated
// across encrypt/walk commands so users get consistent UX.
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

	f.StringVar(&p.encryptedRegex, "encrypted-regex", "",
		"only encrypt keys whose name matches this regex")
	f.StringVar(&p.unencryptedRegex, "unencrypted-regex", "",
		"never encrypt keys whose name matches this regex")
	f.StringVar(&p.encryptedSuffix, "encrypted-suffix", "",
		"only encrypt keys whose name ends with this suffix")
	f.StringVar(&p.unencryptedSuffix, "unencrypted-suffix", "",
		"never encrypt keys whose name ends with this suffix")
	f.BoolVar(&p.macOnlyEncrypted, "mac-only-encrypted", false,
		"compute the message authentication code over encrypted leaves only")
	f.IntVar(&p.shamirThreshold, "shamir-threshold", 0,
		"number of key groups required to recover the data key (0 = sops default)")
}

// encoderOptions returns the cipher.EncoderOptions implied by the flags.
func (p *providerFlags) encoderOptions() cipher.EncoderOptions {
	return cipher.EncoderOptions{
		EncryptedRegex:    p.encryptedRegex,
		UnencryptedRegex:  p.unencryptedRegex,
		EncryptedSuffix:   p.encryptedSuffix,
		UnencryptedSuffix: p.unencryptedSuffix,
		MAC:               macModeFromFlag(p.macOnlyEncrypted),
		ShamirThreshold:   p.shamirThreshold,
	}
}

// keyProvider builds a cipher.KeyProvider from the recipient flags.
// At least one of --age/--kms/--gcp-kms/--vault-uri/--azure-keyvault/--pgp
// must be supplied. --config is consumed by routerForPath in commands
// that support routing.
func (p *providerFlags) keyProvider() (cipher.KeyProvider, error) {
	var providers []cipher.KeyProvider
	if p.age != "" {
		kp, err := cipherage.NewProvider(strutil.SplitCSV(p.age)...)
		if err != nil {
			return nil, err
		}
		providers = append(providers, kp)
	}
	if p.kms != "" {
		ctx, err := parseAWSContext(p.awsCtx)
		if err != nil {
			return nil, err
		}
		opts := kms.ProviderOptions{EncryptionContext: ctx, Profile: p.awsProf}
		kp, err := kms.NewProviderWith(opts, strutil.SplitCSV(p.kms)...)
		if err != nil {
			return nil, err
		}
		providers = append(providers, kp)
	}
	if p.gcpkms != "" {
		kp, err := gcpkms.NewProvider(strutil.SplitCSV(p.gcpkms)...)
		if err != nil {
			return nil, err
		}
		providers = append(providers, kp)
	}
	if p.vault != "" {
		kp, err := vault.NewProvider(strutil.SplitCSV(p.vault)...)
		if err != nil {
			return nil, err
		}
		providers = append(providers, kp)
	}
	if p.azkv != "" {
		kp, err := azkv.NewProvider(strutil.SplitCSV(p.azkv)...)
		if err != nil {
			return nil, err
		}
		providers = append(providers, kp)
	}
	if p.pgp != "" {
		kp, err := pgp.NewProvider(strutil.SplitCSV(p.pgp)...)
		if err != nil {
			return nil, err
		}
		providers = append(providers, kp)
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
// merged keyProvider. Encoder-tuning flags (encrypted-regex,
// unencrypted-regex, encrypted-suffix, unencrypted-suffix,
// mac-only-encrypted, shamir-threshold) thread through in both cases.
func (p *providerFlags) resolveEncoder(_ *cobra.Command) (cipher.Encoder, error) {
	encOpts := p.encoderOptions()
	router, err := p.router()
	if err != nil {
		return nil, err
	}
	if router != nil {
		return cipher.NewRoutedEncoder(router, encOpts), nil
	}
	kp, err := p.keyProvider()
	if err != nil {
		return nil, err
	}
	return cipher.NewEncoderWith(kp, encOpts), nil
}

// parseAWSContext converts repeated `key=value` flag entries into the
// macModeFromFlag maps the --mac-only-encrypted bool flag to a
// MACMode. The CLI runs a single encoder per invocation, so the
// inherit state does not apply here: false maps to MACOnAll, true
// maps to MACOnEncrypted.
func macModeFromFlag(macOnlyEncrypted bool) cipher.MACMode {
	if macOnlyEncrypted {
		return cipher.MACOnEncrypted
	}
	return cipher.MACOnAll
}

// map[string]string sops's KMS context expects.
func parseAWSContext(in []string) (map[string]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(in))
	for _, entry := range in {
		k, v, ok := strings.Cut(entry, "=")
		if !ok {
			return nil, fmt.Errorf("invalid --kms-context entry %q (expect key=value)", entry)
		}
		out[k] = v
	}
	return out, nil
}
