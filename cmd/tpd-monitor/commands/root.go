// Package commands cmd/tpd-monitor/commands/root.go
package commands

import (
	"context"
	"log"
	"log/syslog"
	"os"
	"time"

	logrussyslog "github.com/sirupsen/logrus/hooks/syslog"
	"github.com/skycoin/skywire-utilities/pkg/buildinfo"
	"github.com/skycoin/skywire-utilities/pkg/cipher"
	"github.com/skycoin/skywire-utilities/pkg/cmdutil"
	"github.com/skycoin/skywire-utilities/pkg/logging"
	"github.com/skycoin/skywire-utilities/pkg/tcpproxy"
	"github.com/spf13/cobra"

	"github.com/skycoin/skywire-services/pkg/tpd-monitor/api"
)

var (
	confPath            string
	dmsgURL             string
	arURL               string
	tpdURL              string
	addr                string
	logLvl              string
	tag                 string
	syslogAddr          string
	sleepDeregistration time.Duration
)

func init() {
	RootCmd.Flags().StringVarP(&addr, "addr", "a", ":9080", "address to bind to.\033[0m")
	RootCmd.Flags().DurationVarP(&sleepDeregistration, "sleep-deregistration", "s", 10, "Sleep time for deregistration process in minutes\033[0m")
	RootCmd.Flags().StringVarP(&confPath, "config", "c", "tpd-monitor.json", "config file location.\033[0m")
	RootCmd.Flags().StringVarP(&logLvl, "loglvl", "l", "info", "set log level one of: info, error, warn, debug, trace, panic")
	RootCmd.Flags().StringVar(&dmsgURL, "dmsg-url", "", "url to dmsg data.\033[0m")
	RootCmd.Flags().StringVar(&tpdURL, "tpd-url", "", "url to transport discovery.\033[0m")
	RootCmd.Flags().StringVar(&arURL, "ar-url", "", "url to address resolver.\033[0m")
	RootCmd.Flags().StringVar(&tag, "tag", "tpd-monitor", "logging tag\033[0m")
	RootCmd.Flags().StringVar(&syslogAddr, "syslog", "", "syslog server address. E.g. localhost:514\033[0m")
}

// RootCmd contains the root command
var RootCmd = &cobra.Command{
	Use:   "tpdm",
	Short: "TPD monitor of transport discovery.",
	Long: `
	┌┬┐┌─┐┌┬┐   ┌┬┐┌─┐┌┐┌┬┌┬┐┌─┐┬─┐
	 │ ├─┘ ││───││││ │││││ │ │ │├┬┘
	 ┴ ┴  ─┴┘   ┴ ┴└─┘┘└┘┴ ┴ └─┘┴└─`,
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
		logger := logging.MustGetLogger(tag)
		lvl, err := logging.LevelFromString(logLvl)
		if err != nil {
			logger.Fatal("Invalid loglvl detected")
		}

		logging.SetLevel(lvl)

		conf := api.InitConfig(confPath, mLogger)

		if dmsgURL == "" {
			dmsgURL = conf.Dmsg.Discovery
		}
		if arURL == "" {
			arURL = conf.Transport.AddressResolver
		}
		if tpdURL == "" {
			tpdURL = conf.Transport.Discovery
		}

		var srvURLs api.ServicesURLs
		srvURLs.DMSG = dmsgURL
		srvURLs.TPD = tpdURL
		srvURLs.AR = arURL

		if syslogAddr != "" {
			hook, err := logrussyslog.NewSyslogHook("udp", syslogAddr, syslog.LOG_INFO, tag)
			if err != nil {
				logger.Fatalf("Unable to connect to syslog daemon on %v", syslogAddr)
			}
			logging.AddHook(hook)
		}

		logger.WithField("addr", addr).Info("Serving TPD-Monitor API...")

		monitorSign, _ := cipher.SignPayload([]byte(conf.PK.Hex()), conf.SK) //nolint

		var monitorConfig api.TpdMonitorConfig
		monitorConfig.PK = conf.PK
		monitorConfig.Sign = monitorSign

		tpdMonitorAPI := api.New(logger, srvURLs, monitorConfig)

		ctx, cancel := cmdutil.SignalContext(context.Background(), logger)
		defer cancel()

		go tpdMonitorAPI.InitDeregistrationLoop(ctx, conf, sleepDeregistration)

		go func() {
			if err := tcpproxy.ListenAndServe(addr, tpdMonitorAPI); err != nil {
				logger.Errorf("serve: %v", err)
				cancel()
			}
		}()

		<-ctx.Done()
		if err := tpdMonitorAPI.Visor.Close(); err != nil {
			logger.WithError(err).Error("Visor closed with error.")
		}
	},
}

// Execute executes root CLI command.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		log.Fatal("Failed to execute command: ", err)
	}
}
