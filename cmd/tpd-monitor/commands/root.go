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

	"github.com/SkycoinPro/skywire-services/pkg/tpd-monitor/api"
)

var (
	confPath            string
	dmsgURL             string
	arURL               string
	tpdURL              string
	addr                string
	tag                 string
	syslogAddr          string
	sleepDeregistration time.Duration
)

func init() {
	rootCmd.Flags().StringVarP(&addr, "addr", "a", ":9080", "address to bind to.")
	rootCmd.Flags().DurationVarP(&sleepDeregistration, "sleep-deregistration", "s", 10, "Sleep time for deregistration process in minutes")
	rootCmd.Flags().StringVarP(&confPath, "config", "c", "dmsg-monitor.json", "config file location.")
	rootCmd.Flags().StringVar(&dmsgURL, "dmsg-url", "", "url to dmsg data.")
	rootCmd.Flags().StringVar(&tpdURL, "tpd-url", "", "url to transport discovery.")
	rootCmd.Flags().StringVar(&arURL, "ar-url", "", "url to address resolver.")
	rootCmd.Flags().StringVar(&tag, "tag", "dmsg_monitor", "logging tag")
	rootCmd.Flags().StringVar(&syslogAddr, "syslog", "", "syslog server address. E.g. localhost:514")
}

var rootCmd = &cobra.Command{
	Use:   "tpd-monitor",
	Short: "TPD monitor of transport discovery.",
	Run: func(_ *cobra.Command, _ []string) {
		if _, err := buildinfo.Get().WriteTo(os.Stdout); err != nil {
			log.Printf("Failed to output build info: %v", err)
		}

		mLogger := logging.NewMasterLogger()
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

		logger := mLogger.PackageLogger("tpd_monitor")
		if syslogAddr != "" {
			hook, err := logrussyslog.NewSyslogHook("udp", syslogAddr, syslog.LOG_INFO, tag)
			if err != nil {
				logger.Fatalf("Unable to connect to syslog daemon on %v", syslogAddr)
			}
			logging.AddHook(hook)
		}

		logger.WithField("addr", addr).Info("Serving TPD-Monitor API...")

		monitorSign, _ := cipher.SignPayload([]byte(conf.PK.Hex()), conf.SK) //nolint

		var monitorConfig api.DMSGMonitorConfig
		monitorConfig.PK = conf.PK
		monitorConfig.Sign = monitorSign

		dmsgMonitorAPI := api.New(logger, srvURLs, monitorConfig)

		ctx, cancel := cmdutil.SignalContext(context.Background(), logger)
		defer cancel()

		go dmsgMonitorAPI.InitDeregistrationLoop(ctx, conf, sleepDeregistration)

		go func() {
			if err := tcpproxy.ListenAndServe(addr, dmsgMonitorAPI); err != nil {
				logger.Errorf("serve: %v", err)
				cancel()
			}
		}()

		<-ctx.Done()
		if err := dmsgMonitorAPI.Visor.Close(); err != nil {
			logger.WithError(err).Error("Visor closed with error.")
		}
	},
	Version: buildinfo.Version(),
}

// Execute executes root CLI command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
