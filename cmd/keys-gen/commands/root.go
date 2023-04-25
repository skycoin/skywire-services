// Package commands cmd/keys-gen/commands/root.go
package commands

import (
	"fmt"
	"log"

	"github.com/skycoin/skywire-utilities/pkg/cipher"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "keys-gen",
	Short: "skywire keys generator, prints pub-key and sec-key",
	Run: func(_ *cobra.Command, _ []string) {
		pk, sk := cipher.GenerateKeyPair()
		fmt.Println(pk)
		fmt.Println(sk)
	},
}

// Execute executes root CLI command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
