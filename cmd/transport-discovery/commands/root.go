// Package commands cmd/transport-discovery/root.go
package commands

import (
	"context"
	"fmt"
	"log"
	"log/syslog"
	"os"
	"strings"

	logrussyslog "github.com/sirupsen/logrus/hooks/syslog"
	"github.com/skycoin/dmsg/pkg/direct"
	"github.com/skycoin/dmsg/pkg/dmsg"
	"github.com/skycoin/dmsg/pkg/dmsghttp"
	"github.com/skycoin/skywire-utilities/pkg/buildinfo"
	"github.com/skycoin/skywire-utilities/pkg/cipher"
	"github.com/skycoin/skywire-utilities/pkg/cmdutil"
	"github.com/skycoin/skywire-utilities/pkg/httpauth"
	"github.com/skycoin/skywire-utilities/pkg/logging"
	"github.com/skycoin/skywire-utilities/pkg/metricsutil"
	"github.com/skycoin/skywire-utilities/pkg/storeconfig"
	"github.com/skycoin/skywire-utilities/pkg/tcpproxy"
	"github.com/spf13/cobra"
	"gorm.io/gorm"

	"github.com/skycoin/skywire-services/internal/pg"
	"github.com/skycoin/skywire-services/internal/tpdiscmetrics"
	"github.com/skycoin/skywire-services/pkg/transport-discovery/api"
	"github.com/skycoin/skywire-services/pkg/transport-discovery/store"
)

const (
	redisPrefix = "transport-discovery"
	redisScheme = "redis://"
)

var (
	addr          string
	metricsAddr   string
	redisURL      string
	redisPoolSize int
	pgHost        string
	pgPort        string
	logEnabled    bool
	syslogAddr    string
	tag           string
	testing       bool
	dmsgDisc      string
	sk            cipher.SecKey
)

func init() {
	rootCmd.Flags().StringVarP(&addr, "addr", "a", ":9091", "address to bind to")
	rootCmd.Flags().StringVarP(&metricsAddr, "metrics", "m", "", "address to bind metrics API to")
	rootCmd.Flags().StringVar(&redisURL, "redis", "redis://localhost:6379", "connections string for a redis store")
	rootCmd.Flags().IntVar(&redisPoolSize, "redis-pool-size", 10, "redis connection pool size")
	rootCmd.Flags().StringVar(&pgHost, "pg-host", "localhost", "host of postgres")
	rootCmd.Flags().StringVar(&pgPort, "pg-port", "5432", "port of postgres")
	rootCmd.Flags().BoolVarP(&logEnabled, "log", "l", true, "enable request logging")
	rootCmd.Flags().StringVar(&syslogAddr, "syslog", "", "syslog server address. E.g. localhost:514")
	rootCmd.Flags().StringVar(&tag, "tag", "transport_discovery", "logging tag")
	rootCmd.Flags().BoolVarP(&testing, "testing", "t", false, "enable testing to start without redis")
	rootCmd.Flags().StringVar(&dmsgDisc, "dmsg-disc", "http://dmsgd.skywire.skycoin.com", "url of dmsg-discovery")
	rootCmd.Flags().Var(&sk, "sk", "dmsg secret key")
}

var rootCmd = &cobra.Command{
	Use:   "transport-discovery",
	Short: "Transport Discovery Server for skywire",
	Run: func(_ *cobra.Command, _ []string) {
		if _, err := buildinfo.Get().WriteTo(os.Stdout); err != nil {
			log.Printf("Failed to output build info: %v", err)
		}

		if !strings.HasPrefix(redisURL, redisScheme) {
			redisURL = redisScheme + redisURL
		}

		nonceStoreConfig := storeconfig.Config{
			Type:     storeconfig.Memory,
			URL:      redisURL,
			Password: storeconfig.RedisPassword(),
			PoolSize: redisPoolSize,
		}

		const loggerTag = "transport_discovery"
		logger := logging.MustGetLogger(loggerTag)
		if syslogAddr != "" {
			hook, err := logrussyslog.NewSyslogHook("udp", syslogAddr, syslog.LOG_INFO, tag)
			if err != nil {
				logger.Fatalf("Unable to connect to syslog daemon on %v", syslogAddr)
			}
			logging.AddHook(hook)
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

			nonceStoreConfig.Type = storeconfig.Redis
		}

		s, err := store.New(logger, gormDB, testing)
		if err != nil {
			logger.Fatalf("Failed to create store instance: %v", err)
		}
		defer s.Close()

		ctx, cancel := cmdutil.SignalContext(context.Background(), logger)
		defer cancel()

		nonceStore, err := httpauth.NewNonceStore(ctx, nonceStoreConfig, redisPrefix)
		if err != nil {
			log.Fatal("Failed to initialize redis nonce store: ", err)
		}

		pk, err := sk.PubKey()
		if err != nil {
			logger.WithError(err).Warn("No SecKey found. Skipping serving on dmsghttp.")
		}

		metricsutil.ServeHTTPMetrics(logger, metricsAddr)

		var m tpdiscmetrics.Metrics
		if metricsAddr == "" {
			m = tpdiscmetrics.NewEmpty()
		} else {
			m = tpdiscmetrics.NewVictoriaMetrics()
		}

		enableMetrics := metricsAddr != ""
		tpdAPI := api.New(logger, s, nonceStore, enableMetrics, m)

		logger.Infof("Listening on %s", addr)

		go tpdAPI.RunBackgroundTasks(ctx, logger)

		go func() {
			if err := tcpproxy.ListenAndServe(addr, tpdAPI); err != nil {
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
				if err := dmsghttp.ListenAndServe(ctx, pk, sk, tpdAPI, dClient, dmsg.DefaultDmsgHTTPPort, config, dmsgDC, logger); err != nil {
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
		log.Fatal(err)
	}
}
