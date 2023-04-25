// Package commands cmd/liveness-checker/commands/root.go
package commands

import (
	"context"
	"log"
	"log/syslog"
	"os"
	"strings"

	logrussyslog "github.com/sirupsen/logrus/hooks/syslog"
	"github.com/skycoin/skywire-utilities/pkg/buildinfo"
	"github.com/skycoin/skywire-utilities/pkg/cmdutil"
	"github.com/skycoin/skywire-utilities/pkg/logging"
	"github.com/skycoin/skywire-utilities/pkg/storeconfig"
	"github.com/skycoin/skywire-utilities/pkg/tcpproxy"
	"github.com/spf13/cobra"

	"github.com/SkycoinPro/skywire-services/pkg/liveness-checker/api"
	"github.com/SkycoinPro/skywire-services/pkg/liveness-checker/store"
)

const (
	redisScheme = "redis://"
)

var (
	confPath   string
	addr       string
	tag        string
	syslogAddr string
	redisURL   string
	testing    bool
)

func init() {
	rootCmd.Flags().StringVarP(&addr, "addr", "a", ":9081", "address to bind to.")
	rootCmd.Flags().StringVarP(&confPath, "config", "c", "liveness-checker.json", "config file location.")
	rootCmd.Flags().StringVar(&tag, "tag", "liveness_checker", "logging tag")
	rootCmd.Flags().StringVar(&syslogAddr, "syslog", "", "syslog server address. E.g. localhost:514")
	rootCmd.Flags().StringVar(&redisURL, "redis", "redis://localhost:6379", "connections string for a redis store")
	rootCmd.Flags().BoolVarP(&testing, "testing", "t", false, "enable testing to start without redis")
}

var rootCmd = &cobra.Command{
	Use:   "liveness-checker",
	Short: "Liveness checker of the deployment.",
	Run: func(_ *cobra.Command, _ []string) {
		if _, err := buildinfo.Get().WriteTo(os.Stdout); err != nil {
			log.Printf("Failed to output build info: %v", err)
		}

		if !strings.HasPrefix(redisURL, redisScheme) {
			redisURL = redisScheme + redisURL
		}

		storeConfig := storeconfig.Config{
			Type:     storeconfig.Redis,
			URL:      redisURL,
			Password: storeconfig.RedisPassword(),
		}

		if testing {
			storeConfig.Type = storeconfig.Memory
		}

		mLogger := logging.NewMasterLogger()
		conf, confAPI := api.InitConfig(confPath, mLogger)

		logger := mLogger.PackageLogger(tag)
		if syslogAddr != "" {
			hook, err := logrussyslog.NewSyslogHook("udp", syslogAddr, syslog.LOG_INFO, tag)
			if err != nil {
				logger.Fatalf("Unable to connect to syslog daemon on %v", syslogAddr)
			}
			logging.AddHook(hook)
		}

		ctx, cancel := cmdutil.SignalContext(context.Background(), logger)
		defer cancel()

		s, err := store.New(ctx, storeConfig, logger)
		if err != nil {
			logger.Fatal("Failed to initialize redis store: ", err)
		}

		logger.WithField("addr", addr).Info("Serving discovery API...")

		lcAPI := api.New(conf.PK, conf.SK, s, logger, mLogger, confAPI)

		go lcAPI.RunBackgroundTasks(ctx, conf)

		go func() {
			if err := tcpproxy.ListenAndServe(addr, lcAPI); err != nil {
				logger.Errorf("serve: %v", err)
				cancel()
			}
		}()

		<-ctx.Done()
		if err := lcAPI.Visor.Close(); err != nil {
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
