package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/dcadolph/cipher/precommit"
)

// newPrecommitCmd returns the `cipher precommit` subcommand. Intended
// to be wired into a git pre-commit hook. Exits 1 with a list of
// offending paths on the first violation; exits 0 when staged content
// either does not match the .sops.yaml rules or is already encrypted.
func newPrecommitCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "precommit [PATH...]",
		Short: "Reject any staged file that should be sops-encrypted but is not",
		Long: "With no PATH arguments, scans git-staged files. Otherwise scans the\n" +
			"supplied paths on disk. Exits 1 (with details on stderr) if any file\n" +
			"matches a .sops.yaml creation rule but is not sops-encrypted.",
		RunE: func(cmd *cobra.Command, args []string) error {
			checker, err := buildChecker(configPath)
			if err != nil {
				return err
			}
			var violations []precommit.Violation
			if len(args) == 0 {
				violations, err = checker.CheckStaged()
			} else {
				violations, err = checker.CheckPaths(args)
			}
			if err != nil {
				return err
			}
			if len(violations) == 0 {
				return nil
			}
			for _, v := range violations {
				fmt.Fprintln(os.Stderr, "BLOCKED:", v.Error())
			}
			return fmt.Errorf("%d file(s) violate .sops.yaml", len(violations))
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "",
		"path to .sops.yaml or directory containing it; default searches upward from cwd")
	return cmd
}

// buildChecker returns a precommit.Checker using configPath when set,
// or by walking up from the current working directory.
func buildChecker(configPath string) (*precommit.Checker, error) {
	if configPath != "" {
		return precommit.NewChecker(configPath)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	return precommit.NewCheckerForDir(cwd)
}
