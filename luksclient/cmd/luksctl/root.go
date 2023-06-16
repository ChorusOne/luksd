package luksctl

import (
	"log"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:           "luksclient",
	Short:         "lucksclient",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Usage()
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("error executing luksclient command: %v", err)
		os.Exit(1)
	}
}
