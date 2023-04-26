// Package commands cmd/vpn-monitor/commands/root.go
package commands

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/skycoin/skywire-utilities/pkg/buildinfo"
	"github.com/skycoin/skywire-utilities/pkg/cipher"
	"github.com/skycoin/skywire-utilities/pkg/cmdutil"
	"github.com/skycoin/skywire-utilities/pkg/logging"
	"github.com/skycoin/skywire-utilities/pkg/tcpproxy"
	"github.com/skycoin/skywire/pkg/visor/visorconfig"
	"github.com/spf13/cobra"

	"github.com/skycoin/skywire-services/pkg/vpn-monitor/api"
)

var (
	confPath            string
	addr                string
	tag                 string
	sleepDeregistration time.Duration
)

func init() {
	rootCmd.Flags().StringVarP(&addr, "addr", "a", ":9081", "address to bind to.")
	rootCmd.Flags().DurationVarP(&sleepDeregistration, "sleep-deregistration", "s", 10, "Sleep time for derigstration process in minutes")
	rootCmd.Flags().StringVarP(&confPath, "config", "c", "vpn-monitor.json", "config file location.")
	rootCmd.Flags().StringVar(&tag, "tag", "vpn_monitor", "logging tag")
}

var rootCmd = &cobra.Command{
	Use:   "vpn-monitor",
	Short: "VPN monitor.",
	Run: func(_ *cobra.Command, _ []string) {
		visorBuildInfo := buildinfo.Get()
		if _, err := visorBuildInfo.WriteTo(os.Stdout); err != nil {
			log.Printf("Failed to output build info: %v", err)
		}

		mLogger := logging.NewMasterLogger()
		conf := initConfig(confPath, visorBuildInfo, mLogger)

		fmt.Println(conf.Version)

		srvURLs := api.ServicesURLs{
			SD: conf.Launcher.ServiceDisc,
			UT: conf.UptimeTracker.Addr,
		}

		logger := mLogger.PackageLogger("vpn_monitor")

		logger.WithField("addr", addr).Info("Serving discovery API...")

		vmSign, _ := cipher.SignPayload([]byte(conf.PK.Hex()), conf.SK) //nolint

		vmConfig := api.Config{
			PK:   conf.PK,
			SK:   conf.SK,
			Sign: vmSign,
		}

		vmAPI := api.New(logger, srvURLs, vmConfig)

		ctx, cancel := cmdutil.SignalContext(context.Background(), logger)
		defer cancel()

		go vmAPI.InitDeregistrationLoop(ctx, conf, sleepDeregistration)

		go func() {
			if err := tcpproxy.ListenAndServe(addr, vmAPI); err != nil {
				logger.Errorf("serve: %v", err)
				cancel()
			}
		}()

		<-ctx.Done()
		if err := vmAPI.Visor.Close(); err != nil {
			logger.WithError(err).Error("Visor closed with error.")
		}
	},
	Version: buildinfo.Version(),
}

func initConfig(confPath string, visorBuildInfo *buildinfo.Info, mLog *logging.MasterLogger) *visorconfig.V1 {
	log := mLog.PackageLogger("vpn_monitor:config")
	var r io.Reader

	if confPath != "" {
		log.WithField("filepath", confPath).Info()
		f, err := os.ReadFile(filepath.Clean(confPath))
		if err != nil {
			log.WithError(err).Fatal("Failed to read config file.")
		}
		r = bytes.NewReader(f)
	}

	conf, compat, err := visorconfig.Parse(log, r, confPath, visorBuildInfo)
	if err != nil {
		log.WithError(err).Fatal("Failed to read in config.")
	}
	if !compat {
		log.Fatalf("failed to start skywire - config version is incompatible")
	}

	return conf
}

// Execute executes root CLI command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
