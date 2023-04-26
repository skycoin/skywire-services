// Package commands cmd/config-bootstrapper/commands/root.go
package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/skycoin/skywire-utilities/pkg/buildinfo"
	"github.com/skycoin/skywire-utilities/pkg/cmdutil"
	"github.com/skycoin/skywire-utilities/pkg/logging"
	"github.com/skycoin/skywire-utilities/pkg/tcpproxy"
	"github.com/spf13/cobra"

	"github.com/skycoin/skywire-services/pkg/config-bootstrapper/api"
)

const (
	statusFailure = 1
)

var (
	addr     string
	tag      string
	stunPath string
	domain   string
)

func init() {
	rootCmd.Flags().StringVarP(&addr, "addr", "a", ":9082", "address to bind to")
	rootCmd.Flags().StringVar(&tag, "tag", "address_resolver", "logging tag")
	rootCmd.Flags().StringVarP(&stunPath, "config", "c", "./config.json", "stun server list file location")
	rootCmd.Flags().StringVarP(&domain, "domain", "d", "skywire.skycoin.com", "the domain of the endpoints")
}

var rootCmd = &cobra.Command{
	Use:   "address-resolver",
	Short: "Address Resolver Server for skywire",
	Run: func(_ *cobra.Command, _ []string) {
		if _, err := buildinfo.Get().WriteTo(os.Stdout); err != nil {
			log.Printf("Failed to output build info: %v", err)
		}

		logger := logging.MustGetLogger(tag)
		config := readConfig(logger, stunPath)

		conAPI := api.New(logger, config, domain)
		if logger != nil {
			logger.Infof("Listening on %s", addr)
		}

		ctx, cancel := cmdutil.SignalContext(context.Background(), logger)
		defer cancel()

		go func() {
			if err := tcpproxy.ListenAndServe(addr, conAPI); err != nil {
				logger.Errorf("conAPI.ListenAndServe: %v", err)
				cancel()
			}
		}()

		<-ctx.Done()

		conAPI.Close()
	},
}

func readConfig(log *logging.Logger, confPath string) (config api.Config) {
	var r io.Reader

	f, err := os.Open(confPath) //nolint:gosec
	if err != nil {
		log.WithError(err).
			WithField("filepath", confPath).
			Fatal("Failed to read config file.")
	}
	defer func() { //nolint
		if err := f.Close(); err != nil {
			log.WithError(err).Fatal("Closing config file resulted in error.")
		}
	}()

	r = f

	raw, err := io.ReadAll(r)
	if err != nil {
		log.WithError(err).Fatal("Failed to read in config.")
	}
	conf := api.Config{}

	if err := json.Unmarshal(raw, &conf); err != nil {
		log.WithError(err).Fatal("failed to convert config into json.")
	}

	return conf
}

// Execute executes root CLI command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)

		os.Exit(statusFailure)
	}
}
