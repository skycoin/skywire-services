// Package commands cmd/transport-setup/commands/root.go
package commands

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/skycoin/skywire-utilities/pkg/logging"
	"github.com/spf13/cobra"

	"github.com/SkycoinPro/skywire-services/pkg/transport-setup/api"
	"github.com/SkycoinPro/skywire-services/pkg/transport-setup/config"
)

var configFile string

func init() {
	rootCmd.Flags().StringVarP(&configFile, "config", "c", "", "path to config file")
	err := rootCmd.MarkFlagRequired("config")
	if err != nil {
		log.Fatal("config flag is not specified")
	}
}

var rootCmd = &cobra.Command{
	Use:   "transport-setup [config.json]",
	Short: "Transport setup for skywire",
	Run: func(_ *cobra.Command, args []string) {
		// local config of the client
		const loggerTag = "transport_setup"
		log := logging.MustGetLogger(loggerTag)
		conf := config.MustReadConfig(configFile, log)
		api := api.New(log, conf)
		srv := &http.Server{
			Addr:              fmt.Sprintf(":%d", conf.Port),
			ReadHeaderTimeout: 2 * time.Second,
			IdleTimeout:       30 * time.Second,
			Handler:           api,
		}
		if err := srv.ListenAndServe(); err != nil {
			log.Errorf("ListenAndServe: %v", err)
		}
	},
}

// Execute executes root CLI command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		panic(err)
	}
}
