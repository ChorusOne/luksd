package luksctl

import (
	"github.com/spf13/cobra"
	"github.com/ChorusOne/luksclient/internal/decrypt"
)

var encryptedDevice string

var cmdDecrypt = &cobra.Command{
	Use:   "decrypDevice",
	Short: "decrypt device",
	RunE: func(cmd *cobra.Command, args []string) error {
		decrypt.DecryptDevice(encryptedDevice)
		// if err != nil {
		// 	return panic(err, "error decrypting device")
		// }

		return nil
	},
}

var cmdDecryptTPM = &cobra.Command{
	Use:   "decrypDevice",
	Short: "decrypt device",
	RunE: func(cmd *cobra.Command, args []string) error {
		decrypt.DecryptDeviceTPM(encryptedDevice)
		// if err != nil {
		// 	return panic(err, "error decrypting device")
		// }

		return nil
	},
}

func init() {
	cmdDecrypt.Flags().StringVar(&encryptedDevice, "encrypted-device", "/dev/vdb1", "encrypted device to decrypt")
	cmdDecryptTPM.Flags().StringVar(&encryptedDevice, "encrypted-device", "/dev/vdb1", "encrypted device to decrypt")
	rootCmd.AddCommand(cmdDecrypt)
	rootCmd.AddCommand(cmdDecryptTPM)
}