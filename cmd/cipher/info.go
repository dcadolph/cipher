package main

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/dcadolph/cipher"
)

// newInfoCmd returns the `cipher info PATH` subcommand. It prints the
// metadata of a sops-encrypted file as JSON without decrypting the
// payload.
func newInfoCmd() *cobra.Command {
	var pretty bool
	cmd := &cobra.Command{
		Use:   "info PATH",
		Short: "Print the metadata of a sops-encrypted file as JSON",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			data, err := readPathOrStdin(path)
			if err != nil {
				return err
			}
			info, err := cipher.InspectPath(path, data)
			if err != nil {
				return fmt.Errorf("info %q: %w", path, err)
			}
			enc := json.NewEncoder(cmd.OutOrStdout())
			if pretty {
				enc.SetIndent("", "  ")
			}
			return enc.Encode(info)
		},
	}
	cmd.Flags().BoolVar(&pretty, "pretty", false, "indent the JSON output")
	return cmd
}
