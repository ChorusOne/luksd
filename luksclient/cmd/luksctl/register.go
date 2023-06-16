package luksctl

import (
	"github.com/ChorusOne/luksclient/internal/register"
	"github.com/spf13/cobra"
)

var header string
var key string

var cmdRegisterTPM = &cobra.Command{
	Use:   "registerTPM",
	Short: "register TPM device",
	RunE: func(cmd *cobra.Command, args []string) error {
		register.RegisterClientTPM(header, key)

		return nil
	},
}

var cmdRegister = &cobra.Command{
	Use:   "register",
	Short: "register device",
	RunE: func(cmd *cobra.Command, args []string) error {
		register.RegisterClient(header, key)

		return nil
	},
}

func init() {
	cmdRegisterTPM.Flags().StringVar(&header, "header", "./tpm/hdr.img", "header to register")
	cmdRegisterTPM.Flags().StringVar(&key, "key", "./tpm/password", "key to register")
	cmdRegister.Flags().StringVar(&header, "header", "./tpm/hdr.img", "header to register")
	cmdRegister.Flags().StringVar(&key, "key", "./tpm/password", "key to register")
	rootCmd.AddCommand(cmdRegisterTPM)
	rootCmd.AddCommand(cmdRegister)
}
