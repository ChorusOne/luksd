package luksctl

import (
	"github.com/ChorusOne/luksclient/internal/checkquote"
	"github.com/spf13/cobra"
)

var cmdCheckQuote = &cobra.Command{
	Use:   "checkQuote",
	Short: "checkQuote",
	RunE: func(cmd *cobra.Command, args []string) error {
		checkquote.Check()
		// if err != nil {
		// 	return panic(err, "error decrypting device")
		// }

		return nil
	},
}

func init() {
	rootCmd.AddCommand(cmdCheckQuote)
}
