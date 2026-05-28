package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"

	"github.com/spf13/afero"
	"github.com/spf13/cobra"

	"github.com/dcadolph/cipher"
	"github.com/dcadolph/cipher/sopsconfig"
)

// newRecipientsCmd returns the `cipher recipients` command group with
// list, drift, and orphans subcommands.
func newRecipientsCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "recipients",
		Short: "Inspect and audit recipient sets across encrypted files",
	}
	root.AddCommand(newRecipientsListCmd(), newRecipientsDriftCmd(), newRecipientsOrphansCmd())
	return root
}

// newRecipientsListCmd returns `cipher recipients list PATH`. It prints
// the recipients of a single encrypted file in JSON form.
func newRecipientsListCmd() *cobra.Command {
	var pretty bool
	cmd := &cobra.Command{
		Use:   "list PATH",
		Short: "List the recipients recorded in a sops-encrypted file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			data, err := readPathOrStdin(path)
			if err != nil {
				return err
			}
			info, err := cipher.InspectPath(path, data)
			if err != nil {
				return fmt.Errorf("recipients list %q: %w", path, err)
			}
			enc := json.NewEncoder(cmd.OutOrStdout())
			if pretty {
				enc.SetIndent("", "  ")
			}
			return enc.Encode(info.Groups)
		},
	}
	cmd.Flags().BoolVar(&pretty, "pretty", false, "indent the JSON output")
	return cmd
}

// recipientReport pairs a file path with its recipient diff vs the
// expected set in the .sops.yaml rule.
type recipientReport struct {
	// Path is the file path relative to the walk root.
	Path string `json:"path"`
	// Added are recipients in the file that the rule does not list.
	Added []string `json:"added,omitempty"`
	// Removed are recipients the rule expects that the file lacks.
	Removed []string `json:"removed,omitempty"`
}

// newRecipientsDriftCmd returns `cipher recipients drift ROOT`. For
// each encrypted file under ROOT that matches a creation rule, it
// compares the file's recorded recipients to the rule's expected
// recipients and reports any drift. Files that match no rule are
// skipped.
func newRecipientsDriftCmd() *cobra.Command {
	var configPath string
	var pretty bool
	cmd := &cobra.Command{
		Use:   "drift ROOT",
		Short: "Report files whose recipients diverge from their .sops.yaml rule",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadSopsConfig(configPath)
			if err != nil {
				return err
			}
			reports, err := walkRecipientReports(cmd.Context(), args[0], cfg, false)
			if err != nil {
				return err
			}
			return emitReports(cmd.OutOrStdout(), reports, pretty)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "",
		"path to .sops.yaml or directory containing it")
	cmd.Flags().BoolVar(&pretty, "pretty", false, "indent the JSON output")
	return cmd
}

// newRecipientsOrphansCmd returns `cipher recipients orphans ROOT`.
// It lists files whose recorded recipients include identities the
// .sops.yaml rule no longer expects (i.e. likely stale access).
func newRecipientsOrphansCmd() *cobra.Command {
	var configPath string
	var pretty bool
	cmd := &cobra.Command{
		Use:   "orphans ROOT",
		Short: "Report files with recipients the .sops.yaml rule no longer expects",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadSopsConfig(configPath)
			if err != nil {
				return err
			}
			reports, err := walkRecipientReports(cmd.Context(), args[0], cfg, true)
			if err != nil {
				return err
			}
			return emitReports(cmd.OutOrStdout(), reports, pretty)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "",
		"path to .sops.yaml or directory containing it")
	cmd.Flags().BoolVar(&pretty, "pretty", false, "indent the JSON output")
	return cmd
}

// walkRecipientReports walks root and, for each encrypted file matched
// by a creation rule in cfg, returns a recipientReport summarizing
// drift between actual recipients and the rule's expected set. When
// onlyOrphans is true, reports with no Added entries are omitted.
func walkRecipientReports(
	ctx context.Context, root string,
	cfg *sopsconfig.Config, onlyOrphans bool,
) ([]recipientReport, error) {
	router := cfg.Router(nil)
	files := afero.NewOsFs()
	var reports []recipientReport

	err := afero.Walk(files, root, func(path string, info fs.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		matched, err := cfg.MatchesAnyRule(path, nil)
		if err != nil {
			return fmt.Errorf("match %q: %w", path, err)
		}
		if !matched {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %q: %w", path, err)
		}
		if !cipher.IsEncryptedPath(path, data) {
			return nil
		}
		actual, err := cipher.InspectPath(path, data)
		if err != nil {
			return fmt.Errorf("inspect %q: %w", path, err)
		}
		expected, err := expectedRecipientSet(ctx, router, path)
		if err != nil {
			return fmt.Errorf("expected recipients %q: %w", path, err)
		}
		actualSet := flattenRecipientSet(actual)
		report := recipientReport{
			Path:    path,
			Added:   sortedDiff(actualSet, expected),
			Removed: sortedDiff(expected, actualSet),
		}
		if onlyOrphans && len(report.Added) == 0 {
			return nil
		}
		if len(report.Added) == 0 && len(report.Removed) == 0 {
			return nil
		}
		reports = append(reports, report)
		return nil
	})
	return reports, err
}

// expectedRecipientSet returns the recipient identifiers the router's
// KeyProvider would attach to path, as "<type>:<id>" strings.
func expectedRecipientSet(
	ctx context.Context, router cipher.Router, path string,
) (map[string]struct{}, error) {
	kp, _, err := router.Resolve(path)
	if err != nil {
		return nil, err
	}
	groups, err := kp.KeyGroups(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]struct{})
	for _, g := range groups {
		for _, k := range g {
			out[k.TypeToIdentifier()+":"+k.ToString()] = struct{}{}
		}
	}
	return out, nil
}

// flattenRecipientSet flattens an Inspect result to the set of
// "<type>:<id>" strings.
func flattenRecipientSet(info *cipher.Info) map[string]struct{} {
	out := make(map[string]struct{})
	for _, g := range info.Groups {
		for _, r := range g {
			out[r.Type+":"+r.Identifier] = struct{}{}
		}
	}
	return out
}

// sortedDiff returns members of a that are not in b, sorted.
func sortedDiff(a, b map[string]struct{}) []string {
	var out []string
	for id := range a {
		if _, ok := b[id]; !ok {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// emitReports JSON-encodes reports to w, optionally indented.
func emitReports(w io.Writer, reports []recipientReport, pretty bool) error {
	enc := json.NewEncoder(w)
	if pretty {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(reports)
}
