// Package commands cmd/node-visualizer/commands/root.go
package commands

import (
	"context"
	"log"
	"log/syslog"
	"net/http"
	"os"
	"time"

	logrussyslog "github.com/sirupsen/logrus/hooks/syslog"
	"github.com/skycoin/skywire-utilities/pkg/buildinfo"
	"github.com/skycoin/skywire-utilities/pkg/cmdutil"
	"github.com/skycoin/skywire-utilities/pkg/logging"
	"github.com/skycoin/skywire-utilities/pkg/metricsutil"
	"github.com/spf13/cobra"

	"github.com/skycoin/skywire-services/internal/tpdiscmetrics"
	"github.com/skycoin/skywire-services/pkg/node-visualizer/api"
)

var (
	addr        string
	metricsAddr string
	logEnabled  bool
	syslogAddr  string
	tag         string
	testing     bool
)

func init() {
	RootCmd.Flags().StringVarP(&addr, "addr", "a", ":9081", "address to bind to\033[0m")
	RootCmd.Flags().StringVarP(&metricsAddr, "metrics", "m", "", "address to bind metrics API to\033[0m")
	RootCmd.Flags().BoolVarP(&logEnabled, "log", "l", true, "enable request logging\033[0m")
	RootCmd.Flags().StringVar(&syslogAddr, "syslog", "", "syslog server address. E.g. localhost:514\033[0m")
	RootCmd.Flags().StringVar(&tag, "tag", "node-visualizer", "logging tag\033[0m")
	RootCmd.Flags().BoolVarP(&testing, "testing", "t", false, "enable testing to start without redis\033[0m")
}

// RootCmd contains the root command
var RootCmd = &cobra.Command{
	Use:   "nv",
	Short: "Node Visualizer Server for skywire",
	Long: `
	┌┐┌┌─┐┌┬┐┌─┐  ┬  ┬┬┌─┐┬ ┬┌─┐┬  ┬┌─┐┌─┐┬─┐
	││││ │ ││├┤───└┐┌┘│└─┐│ │├─┤│  │┌─┘├┤ ├┬┘
	┘└┘└─┘─┴┘└─┘   └┘ ┴└─┘└─┘┴ ┴┴─┘┴└─┘└─┘┴└─`,
	SilenceErrors:         true,
	SilenceUsage:          true,
	DisableSuggestions:    true,
	DisableFlagsInUseLine: true,
	Version:               buildinfo.Version(),
	Run: func(_ *cobra.Command, _ []string) {
		if _, err := buildinfo.Get().WriteTo(os.Stdout); err != nil {
			log.Printf("Failed to output build info: %v", err)
		}

		const loggerTag = "node_visualizer"
		logger := logging.MustGetLogger(loggerTag)
		if syslogAddr != "" {
			hook, err := logrussyslog.NewSyslogHook("udp", syslogAddr, syslog.LOG_INFO, tag)
			if err != nil {
				logger.Fatalf("Unable to connect to syslog daemon on %v", syslogAddr)
			}
			logging.AddHook(hook)
		}

		metricsutil.ServeHTTPMetrics(logger, metricsAddr)

		var m tpdiscmetrics.Metrics
		if metricsAddr == "" {
			m = tpdiscmetrics.NewEmpty()
		} else {
			m = tpdiscmetrics.NewVictoriaMetrics()
		}

		enableMetrics := metricsAddr != ""
		nvAPI := api.New(logger, enableMetrics, m)

		logger.Infof("Listening on %s", addr)
		ctx, cancel := cmdutil.SignalContext(context.Background(), logger)
		defer cancel()
		go nvAPI.RunBackgroundTasks(ctx, logger)
		go func() {
			srv := &http.Server{
				Addr:              addr,
				ReadHeaderTimeout: 2 * time.Second,
				IdleTimeout:       30 * time.Second,
				Handler:           nvAPI,
			}
			if err := srv.ListenAndServe(); err != nil {
				logger.Errorf("ListenAndServe: %v", err)
				cancel()
			}
		}()
		<-ctx.Done()
	},
}

// Execute executes root CLI command.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		log.Fatal("Failed to execute command: ", err)
	}
}
