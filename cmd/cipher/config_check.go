package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"

	"github.com/dcadolph/cipher/azkv"
	"github.com/dcadolph/cipher/gcpkms"
	"github.com/dcadolph/cipher/kms"
	"github.com/dcadolph/cipher/pgp"
	"github.com/dcadolph/cipher/sopsconfig"
	"github.com/dcadolph/cipher/vault"
)

// newConfigCmd returns the `cipher config` command group.
func newConfigCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "config",
		Short: "Inspect and validate .sops.yaml",
	}
	root.AddCommand(newConfigCheckCmd())
	return root
}

// newConfigCheckCmd returns `cipher config check [PATH]`. It validates
// the project's .sops.yaml: regexes compile, every rule has at least
// one recipient, and every recipient identifier parses through the
// corresponding provider's validating constructor.
func newConfigCheckCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check [PATH]",
		Short: "Validate .sops.yaml: regex syntax, recipient shapes, key-group reachability",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var configPath string
			if len(args) == 1 {
				configPath = args[0]
			}
			cfg, err := loadSopsConfig(configPath)
			if err != nil {
				return err
			}
			problems, err := checkConfig(cfg)
			if err != nil {
				return err
			}
			if len(problems) == 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "ok: %s\n", cfg.Path)
				return nil
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "found %d problem(s) in %s:\n", len(problems), cfg.Path)
			for _, p := range problems {
				fmt.Fprintln(cmd.ErrOrStderr(), "  -", p)
			}
			return fmt.Errorf("%d problem(s) found", len(problems))
		},
	}
	return cmd
}

// rawSopsConfig is the subset of .sops.yaml we need to validate.
type rawSopsConfig struct {
	CreationRules []rawCreationRule `yaml:"creation_rules"`
}

// rawCreationRule mirrors the per-rule fields we care about. Long-form
// key groups via key_groups are flattened with the inline recipients
// before validation.
type rawCreationRule struct {
	PathRegex        string        `yaml:"path_regex"`
	Age              string        `yaml:"age"`
	KMS              string        `yaml:"kms"`
	GCPKMS           string        `yaml:"gcp_kms"`
	PGP              string        `yaml:"pgp"`
	AzureKV          string        `yaml:"azure_keyvault"`
	HCVault          string        `yaml:"hc_vault_transit_uri"`
	KeyGroups        []rawKeyGroup `yaml:"key_groups"`
	EncryptedRegex   string        `yaml:"encrypted_regex"`
	UnencryptedRegex string        `yaml:"unencrypted_regex"`
	ShamirThreshold  int           `yaml:"shamir_threshold"`
}

// rawKeyGroup mirrors a single entry under key_groups. Each list-typed
// field accepts both a single string and a list in the underlying
// YAML; we normalize via UnmarshalYAML.
type rawKeyGroup struct {
	Age     []string `yaml:"age"`
	KMS     []string `yaml:"kms"`
	GCPKMS  []string `yaml:"gcp_kms"`
	PGP     []string `yaml:"pgp"`
	AzureKV []string `yaml:"azure_keyvault"`
	HCVault []string `yaml:"hc_vault_transit_uri"`
}

// checkConfig validates cfg by parsing its raw YAML and surfacing every
// problem found. An empty slice means the config validates cleanly.
func checkConfig(cfg *sopsconfig.Config) ([]string, error) {
	data, err := os.ReadFile(cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", cfg.Path, err)
	}
	var raw rawSopsConfig
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse %q: %w", cfg.Path, err)
	}
	if len(raw.CreationRules) == 0 {
		return []string{"no creation_rules defined"}, nil
	}
	var problems []string
	for i, rule := range raw.CreationRules {
		problems = append(problems, checkRule(i, rule)...)
	}
	return problems, nil
}

// checkRule validates one creation_rule and returns a list of problem
// strings prefixed with rule index.
func checkRule(index int, rule rawCreationRule) []string {
	var problems []string
	prefix := fmt.Sprintf("rule[%d]", index)

	if rule.PathRegex == "" {
		problems = append(problems, prefix+": path_regex is empty")
	} else if _, err := regexp.Compile(rule.PathRegex); err != nil {
		problems = append(problems,
			fmt.Sprintf("%s: path_regex %q: %v", prefix, rule.PathRegex, err))
	}
	if rule.EncryptedRegex != "" {
		if _, err := regexp.Compile(rule.EncryptedRegex); err != nil {
			problems = append(problems,
				fmt.Sprintf("%s: encrypted_regex %q: %v", prefix, rule.EncryptedRegex, err))
		}
	}
	if rule.UnencryptedRegex != "" {
		if _, err := regexp.Compile(rule.UnencryptedRegex); err != nil {
			problems = append(problems,
				fmt.Sprintf("%s: unencrypted_regex %q: %v", prefix, rule.UnencryptedRegex, err))
		}
	}

	inlineCount := countRecipients(rule)
	groupCount := 0
	for _, g := range rule.KeyGroups {
		groupCount += countGroupRecipients(g)
	}
	if inlineCount+groupCount == 0 {
		problems = append(problems, prefix+
			": no recipients (no age/kms/gcp_kms/pgp/azure_keyvault/vault, no key_groups)")
	}

	problems = append(problems, validateCSVRecipients(prefix, "age", rule.Age, nil)...)
	problems = append(problems, validateCSVRecipients(prefix, "kms", rule.KMS, kmsValidator)...)
	problems = append(problems,
		validateCSVRecipients(prefix, "gcp_kms", rule.GCPKMS, gcpkmsValidator)...)
	problems = append(problems, validateCSVRecipients(prefix, "pgp", rule.PGP, pgpValidator)...)
	problems = append(problems,
		validateCSVRecipients(prefix, "azure_keyvault", rule.AzureKV, azkvValidator)...)
	problems = append(problems,
		validateCSVRecipients(prefix, "hc_vault_transit_uri", rule.HCVault, vaultValidator)...)

	for gi, g := range rule.KeyGroups {
		gPrefix := fmt.Sprintf("%s.key_groups[%d]", prefix, gi)
		problems = append(problems, validateRecipients(gPrefix, "age", g.Age, nil)...)
		problems = append(problems, validateRecipients(gPrefix, "kms", g.KMS, kmsValidator)...)
		problems = append(problems,
			validateRecipients(gPrefix, "gcp_kms", g.GCPKMS, gcpkmsValidator)...)
		problems = append(problems, validateRecipients(gPrefix, "pgp", g.PGP, pgpValidator)...)
		problems = append(problems,
			validateRecipients(gPrefix, "azure_keyvault", g.AzureKV, azkvValidator)...)
		problems = append(problems,
			validateRecipients(gPrefix, "hc_vault_transit_uri", g.HCVault, vaultValidator)...)
	}

	if rule.ShamirThreshold != 0 && rule.ShamirThreshold > len(rule.KeyGroups) {
		problems = append(problems, fmt.Sprintf(
			"%s: shamir_threshold=%d exceeds key_groups count=%d",
			prefix, rule.ShamirThreshold, len(rule.KeyGroups),
		))
	}
	return problems
}

// countRecipients returns the number of inline recipients (across all
// types) on a rule.
func countRecipients(rule rawCreationRule) int {
	n := 0
	csvFields := []string{
		rule.Age, rule.KMS, rule.GCPKMS,
		rule.PGP, rule.AzureKV, rule.HCVault,
	}
	for _, csv := range csvFields {
		for v := range strings.SplitSeq(csv, ",") {
			if strings.TrimSpace(v) != "" {
				n++
			}
		}
	}
	return n
}

// countGroupRecipients returns the total recipient count in a key group.
func countGroupRecipients(g rawKeyGroup) int {
	return len(g.Age) + len(g.KMS) + len(g.GCPKMS) + len(g.PGP) + len(g.AzureKV) + len(g.HCVault)
}

// recipientValidator validates one recipient identifier. Returning a
// non-nil error means the identifier is malformed. A nil validator
// short-circuits (no checks beyond emptiness).
type recipientValidator func(id string) error

var (
	kmsValidator = func(id string) error {
		_, err := kms.NewProvider(id)
		return err
	}
	gcpkmsValidator = func(id string) error {
		_, err := gcpkms.NewProvider(id)
		return err
	}
	pgpValidator = func(id string) error {
		_, err := pgp.NewProvider(id)
		return err
	}
	azkvValidator = func(id string) error {
		_, err := azkv.NewProvider(id)
		return err
	}
	vaultValidator = func(id string) error {
		_, err := vault.NewProvider(id)
		return err
	}
)

// validateCSVRecipients runs each comma-separated entry of csv through
// validate and returns a problem string per invalid entry.
func validateCSVRecipients(prefix, field, csv string, validate recipientValidator) []string {
	if csv == "" {
		return nil
	}
	return validateRecipients(prefix, field, strings.Split(csv, ","), validate)
}

// validateRecipients runs each entry through validate and returns a
// problem string per invalid entry.
func validateRecipients(
	prefix, field string, entries []string, validate recipientValidator,
) []string {
	var problems []string
	for _, raw := range entries {
		id := strings.TrimSpace(raw)
		if id == "" {
			continue
		}
		if validate == nil {
			continue
		}
		if err := validate(id); err != nil {
			problems = append(problems,
				fmt.Sprintf("%s.%s %q: %v", prefix, field, id, err))
		}
	}
	return problems
}
