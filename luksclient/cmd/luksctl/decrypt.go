package luksctl

import (
	"github.com/ChorusOne/luksclient/internal/decrypt"
	"github.com/spf13/cobra"
)

var encryptedDevice string
var method string

var cmdDecrypt = &cobra.Command{
	Use:   "decrypt",
	Short: "decrypt",
	RunE: func(cmd *cobra.Command, args []string) error {
		decrypt.DecryptDevice(encryptedDevice, method)
		
		return nil
	},
}

func init() {
	cmdDecrypt.Flags().StringVar(&encryptedDevice, "encrypted-device", "/dev/vdb1", "encrypted device to decrypt")
	cmdDecrypt.Flags().StringVar(&method, "deencryption method", "disk", "can be disk or tpm")
	rootCmd.AddCommand(cmdDecrypt)
}
