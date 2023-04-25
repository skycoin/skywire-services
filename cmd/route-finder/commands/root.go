// Package commands cmd/route-finder/commands/root.go
package commands

import (
	"context"
	"fmt"
	"log"
	"log/syslog"
	"os"

	logrussyslog "github.com/sirupsen/logrus/hooks/syslog"
	"github.com/skycoin/dmsg/pkg/direct"
	"github.com/skycoin/dmsg/pkg/dmsg"
	"github.com/skycoin/dmsg/pkg/dmsghttp"
	"github.com/skycoin/skywire-utilities/pkg/buildinfo"
	"github.com/skycoin/skywire-utilities/pkg/cipher"
	"github.com/skycoin/skywire-utilities/pkg/cmdutil"
	"github.com/skycoin/skywire-utilities/pkg/logging"
	"github.com/skycoin/skywire-utilities/pkg/metricsutil"
	"github.com/skycoin/skywire-utilities/pkg/storeconfig"
	"github.com/skycoin/skywire-utilities/pkg/tcpproxy"
	"github.com/spf13/cobra"
	"gorm.io/gorm"

	"github.com/SkycoinPro/skywire-services/internal/pg"
	"github.com/SkycoinPro/skywire-services/pkg/route-finder/api"
	"github.com/SkycoinPro/skywire-services/pkg/transport-discovery/store"
)

const (
	statusFailure = 1
)

var (
	addr        string
	metricsAddr string
	pgHost      string
	pgPort      string
	logEnabled  bool
	syslogAddr  string
	tag         string
	testing     bool
	dmsgDisc    string
	sk          cipher.SecKey
)

func init() {
	rootCmd.Flags().StringVarP(&addr, "addr", "a", ":9092", "address to bind to")
	rootCmd.Flags().StringVarP(&metricsAddr, "metrics", "m", "", "address to bind metrics API to")
	rootCmd.Flags().BoolVarP(&logEnabled, "log", "l", true, "enable request logging")
	rootCmd.Flags().StringVar(&pgHost, "pg-host", "localhost", "host of postgres")
	rootCmd.Flags().StringVar(&pgPort, "pg-port", "5432", "port of postgres")
	rootCmd.Flags().StringVar(&syslogAddr, "syslog", "", "syslog server address. E.g. localhost:514")
	rootCmd.Flags().StringVar(&tag, "tag", "route_finder", "logging tag")
	rootCmd.Flags().BoolVarP(&testing, "testing", "t", false, "enable testing to start without redis")
	rootCmd.Flags().StringVar(&dmsgDisc, "dmsg-disc", "http://dmsgd.skywire.skycoin.com", "url of dmsg-discovery")
	rootCmd.Flags().Var(&sk, "sk", "dmsg secret key")
}

var rootCmd = &cobra.Command{
	Use:   "route-finder",
	Short: "Route Finder Server for skywire",
	Run: func(_ *cobra.Command, _ []string) {
		if _, err := buildinfo.Get().WriteTo(os.Stdout); err != nil {
			log.Printf("Failed to output build info: %v", err)
		}

		memoryStore := true

		var logger *logging.Logger
		if logEnabled {
			logger = logging.MustGetLogger(tag)
		} else {
			logger = nil
		}

		var gormDB *gorm.DB
		var err error

		if !testing {
			pgUser, pgPassword, pgDatabase := storeconfig.PostgresCredential()
			dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
				pgHost,
				pgPort,
				pgUser,
				pgPassword,
				pgDatabase)

			gormDB, err = pg.Init(dsn)
			if err != nil {
				logger.Fatalf("Failed to connect to database %v", err)
			}
			logger.Printf("Database connected.")
			memoryStore = false
		}

		transportStore, err := store.New(logger, gormDB, memoryStore)
		if err != nil {
			log.Fatal("Failed to initialize redis store: ", err)
		}

		pk, err := sk.PubKey()
		if err != nil {
			logger.WithError(err).Warn("No SecKey found. Skipping serving on dmsghttp.")
		}

		if syslogAddr != "" {
			hook, err := logrussyslog.NewSyslogHook("udp", syslogAddr, syslog.LOG_INFO, tag)
			if err != nil && logger != nil {
				logger.Fatalf("Unable to connect to syslog daemon on %v", syslogAddr)
			}
			logging.AddHook(hook)
		}

		metricsutil.ServeHTTPMetrics(logger, metricsAddr)

		enableMetrics := metricsAddr != ""
		rfAPI := api.New(transportStore, logger, enableMetrics)

		if logger != nil {
			logger.Infof("Listening on %s", addr)
		}

		ctx, cancel := cmdutil.SignalContext(context.Background(), logger)
		defer cancel()

		go func() {
			if err := tcpproxy.ListenAndServe(addr, rfAPI); err != nil {
				logger.Errorf("tcpproxy.ListenAndServe: %v", err)
				cancel()
			}
		}()

		if !pk.Null() {
			servers := dmsghttp.GetServers(ctx, dmsgDisc, logger)

			var keys cipher.PubKeys
			keys = append(keys, pk)
			dClient := direct.NewClient(direct.GetAllEntries(keys, servers), logger)
			config := &dmsg.Config{
				MinSessions:    0, // listen on all available servers
				UpdateInterval: dmsg.DefaultUpdateInterval,
			}

			dmsgDC, closeDmsgDC, err := direct.StartDmsg(ctx, logger, pk, sk, dClient, config)
			if err != nil {
				logger.WithError(err).Fatal("failed to start direct dmsg client.")
			}

			defer closeDmsgDC()

			go dmsghttp.UpdateServers(ctx, dClient, dmsgDisc, dmsgDC, logger)

			go func() {
				if err := dmsghttp.ListenAndServe(ctx, pk, sk, rfAPI, dClient, dmsg.DefaultDmsgHTTPPort, config, dmsgDC, logger); err != nil {
					logger.Errorf("dmsghttp.ListenAndServe: %v", err)
					cancel()
				}
			}()
		}

		<-ctx.Done()
	},
}

// Execute executes root CLI command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)

		os.Exit(statusFailure)
	}
}
