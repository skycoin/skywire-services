// Package commands cmd/network-monitor/commands/root.go
package commands

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/skycoin/skywire-utilities/pkg/buildinfo"
	"github.com/skycoin/skywire-utilities/pkg/cipher"
	"github.com/skycoin/skywire-utilities/pkg/logging"
	"github.com/skycoin/skywire-utilities/pkg/tcpproxy"
	"github.com/spf13/cobra"

	"github.com/skycoin/skywire-services/internal/monitors"
	"github.com/skycoin/skywire-services/pkg/network-monitor/api"
)

var (
	confPath            string
	dmsgURL             string
	utURL               string
	arURL               string
	addr                string
	tag                 string
	logLvl              string
	sleepDeregistration time.Duration
)

func init() {
	RootCmd.Flags().StringVarP(&addr, "addr", "a", "", "address to bind to.\033[0m")
	RootCmd.Flags().DurationVarP(&sleepDeregistration, "sleep-deregistration", "s", 0, "Sleep time for derigstration process in minutes\033[0m")
	RootCmd.Flags().StringVar(&dmsgURL, "dmsg-url", "", "url to dmsg data.\033[0m")
	RootCmd.Flags().StringVar(&utURL, "ut-url", "", "url to uptime tracker visor data.\033[0m")
	RootCmd.Flags().StringVar(&arURL, "ar-url", "", "url to ar data.\033[0m")
	RootCmd.Flags().StringVarP(&confPath, "config", "c", "network-monitor.json", "path of network-monitor config\033[0m")
	RootCmd.Flags().StringVar(&tag, "tag", "network_monitor", "logging tag\033[0m")
	RootCmd.Flags().StringVarP(&logLvl, "loglvl", "l", "", "set log level one of: info, error, warn, debug, trace, panic")
}

// RootCmd contains the root command
var RootCmd = &cobra.Command{
	Use: func() string {
		return strings.Split(filepath.Base(strings.ReplaceAll(strings.ReplaceAll(fmt.Sprintf("%v", os.Args), "[", ""), "]", "")), " ")[0]
	}(),
	Short: "DMSG monitor of DMSG discovery entries.",
	Long: `
	┌┐┌┌─┐┌┬┐┬ ┬┌─┐┬─┐┬┌─   ┌┬┐┌─┐┌┐┌┬┌┬┐┌─┐┬─┐
	│││├┤  │ ││││ │├┬┘├┴┐───││││ │││││ │ │ │├┬┘
	┘└┘└─┘ ┴ └┴┘└─┘┴└─┴ ┴   ┴ ┴└─┘┘└┘┴ ┴ └─┘┴└─`,
	SilenceErrors:         true,
	SilenceUsage:          true,
	DisableSuggestions:    true,
	DisableFlagsInUseLine: true,
	Version:               buildinfo.Version(),
	Run: func(_ *cobra.Command, _ []string) {
		if _, err := buildinfo.Get().WriteTo(os.Stdout); err != nil {
			log.Printf("Failed to output build info: %v", err)
		}

		mLogger := logging.NewMasterLogger()
		conf, err := monitors.ReadConfig(confPath)
		if err != nil {
			mLogger.Fatal("Invalid config file")
		}

		// use overwrite config values if flags not set
		if dmsgURL == "" {
			dmsgURL = conf.DMSGUrl
		}
		if utURL == "" {
			utURL = conf.UTUrl + "/uptimes"
		}
		if arURL == "" {
			arURL = conf.ARUrl
		}
		if addr == "" {
			addr = conf.Addr
		}
		if sleepDeregistration == 0 {
			sleepDeregistration = conf.SleepDeregistration
		}
		if logLvl == "" {
			logLvl = conf.LogLevel
		}

		lvl, err := logging.LevelFromString(logLvl)
		if err != nil {
			mLogger.Fatal("Invalid log level")
		}
		logging.SetLevel(lvl)

		logger := mLogger.PackageLogger(tag)

		logger.WithField("addr", addr).Info("Serving DMSG-Monitor API...")

		monitorSign, _ := cipher.SignPayload([]byte(conf.PK.Hex()), conf.SK) //nolint

		var monitorConfig api.MonitorConfig
		monitorConfig.PK = conf.PK
		monitorConfig.Sign = monitorSign
		monitorConfig.DMSG = dmsgURL
		monitorConfig.UT = utURL
		monitorConfig.AR = arURL

		dmsgMonitorAPI := api.New(logger, monitorConfig)

		go dmsgMonitorAPI.InitDeregistrationLoop(sleepDeregistration)

		if err := tcpproxy.ListenAndServe(addr, dmsgMonitorAPI); err != nil {
			logger.Errorf("serve: %v", err)
		}
	},
}

// Execute executes root CLI command.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		log.Fatal("Failed to execute command: ", err)
	}
}
