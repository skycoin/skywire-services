// Package commands cmd/uptime-tracker/commands/root.go
package commands

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/skycoin/dmsg/pkg/direct"
	"github.com/skycoin/dmsg/pkg/dmsg"
	"github.com/skycoin/dmsg/pkg/dmsghttp"
	"github.com/skycoin/skywire-utilities/pkg/buildinfo"
	"github.com/skycoin/skywire-utilities/pkg/cipher"
	"github.com/skycoin/skywire-utilities/pkg/cmdutil"
	"github.com/skycoin/skywire-utilities/pkg/geo"
	"github.com/skycoin/skywire-utilities/pkg/httpauth"
	"github.com/skycoin/skywire-utilities/pkg/logging"
	"github.com/skycoin/skywire-utilities/pkg/metricsutil"
	"github.com/skycoin/skywire-utilities/pkg/storeconfig"
	"github.com/skycoin/skywire-utilities/pkg/tcpproxy"
	"github.com/spf13/cobra"
	"gorm.io/gorm"

	"github.com/skycoin/skywire-services/internal/pg"
	"github.com/skycoin/skywire-services/internal/utmetrics"
	"github.com/skycoin/skywire-services/pkg/uptime-tracker/api"
	"github.com/skycoin/skywire-services/pkg/uptime-tracker/store"
)

const (
	statusFailure = 1
	redisPrefix   = "uptime-tracker"
	redisScheme   = "redis://"
)

var (
	addr              string
	pAddr             string
	metricsAddr       string
	redisURL          string
	redisPoolSize     int
	pgHost            string
	pgPort            string
	pgMaxOpenConn     int
	logEnabled        bool
	tag               string
	ipAPIKey          string
	enableLoadTesting bool
	testing           bool
	dmsgDisc          string
	sk                cipher.SecKey
	dmsgPort          uint16
	storeDataCutoff   int
	storeDataPath     string
)

func init() {
	rootCmd.Flags().StringVarP(&addr, "addr", "a", ":9096", "address to bind to")
	rootCmd.Flags().StringVarP(&pAddr, "private-addr", "p", ":9086", "private address to bind to")
	rootCmd.Flags().StringVarP(&metricsAddr, "metrics", "m", ":2121", "address to bind metrics API to")
	rootCmd.Flags().StringVar(&redisURL, "redis", "redis://localhost:6379", "connections string for a redis store")
	rootCmd.Flags().IntVar(&redisPoolSize, "redis-pool-size", 10, "redis connection pool size")
	rootCmd.Flags().StringVar(&pgHost, "pg-host", "localhost", "host of postgres")
	rootCmd.Flags().StringVar(&pgPort, "pg-port", "5432", "port of postgres")
	rootCmd.Flags().IntVar(&pgMaxOpenConn, "pg-max-open-conn", 60, "maximum open connection of db")
	rootCmd.Flags().IntVar(&storeDataCutoff, "store-data-cutoff", 7, "number of days data store in db")
	rootCmd.Flags().StringVar(&storeDataPath, "store-data-path", "/var/lib/skywire-ut/daily-data", "path of db daily data store")
	rootCmd.Flags().BoolVarP(&logEnabled, "log", "l", true, "enable request logging")
	rootCmd.Flags().StringVar(&tag, "tag", "uptime_tracker", "logging tag")
	rootCmd.Flags().StringVar(&ipAPIKey, "ip-api-key", "", "geo API key")
	rootCmd.Flags().BoolVar(&enableLoadTesting, "enable-load-testing", false, "enable load testing")
	rootCmd.Flags().BoolVarP(&testing, "testing", "t", false, "enable testing to start without redis")
	rootCmd.Flags().StringVar(&dmsgDisc, "dmsg-disc", "http://dmsgd.skywire.skycoin.com", "url of dmsg-discovery")
	rootCmd.Flags().Var(&sk, "sk", "dmsg secret key")
	rootCmd.Flags().Uint16Var(&dmsgPort, "dmsgPort", dmsg.DefaultDmsgHTTPPort, "dmsg port value\r")
}

var rootCmd = &cobra.Command{
	Use:   "uptime-tracker",
	Short: "Uptime Tracker Server for skywire",
	Run: func(_ *cobra.Command, _ []string) {
		if _, err := buildinfo.Get().WriteTo(os.Stdout); err != nil {
			log.Printf("Failed to output build info: %v", err)
		}

		if !strings.HasPrefix(redisURL, redisScheme) {
			redisURL = redisScheme + redisURL
		}

		const loggerTag = "uptime_tracker"
		logger := logging.MustGetLogger(loggerTag)

		var gormDB *gorm.DB

		pk, err := sk.PubKey()
		if err != nil {
			logger.WithError(err).Warn("No SecKey found. Skipping serving on dmsghttp.")
		}

		nonceStoreConfig := storeconfig.Config{
			Type:     storeconfig.Memory,
			URL:      redisURL,
			Password: storeconfig.RedisPassword(),
		}

		if !testing {
			pgUser, pgPassword, pgDatabase := storeconfig.PostgresCredential()
			dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
				pgHost,
				pgPort,
				pgUser,
				pgPassword,
				pgDatabase)

			gormDB, err = pg.Init(dsn, pgMaxOpenConn)
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
			logger.Fatal("Failed to initialize redis nonce store: ", err)
		}

		locDetails := geo.MakeIPDetails(logging.MustGetLogger("uptime.geo"), ipAPIKey)

		metricsutil.ServeHTTPMetrics(logger, metricsAddr)

		var m utmetrics.Metrics
		if metricsAddr == "" {
			m = utmetrics.NewEmpty()
		} else {
			m = utmetrics.NewVictoriaMetrics()
		}

		var dmsgAddr string
		if !pk.Null() {
			dmsgAddr = fmt.Sprintf("%s:%d", pk.Hex(), dmsgPort)
		}

		enableMetrics := metricsAddr != ""
		utAPI := api.New(logger, s, nonceStore, locDetails, enableLoadTesting, enableMetrics, m, storeDataCutoff, storeDataPath, dmsgAddr)

		utPAPI := api.NewPrivate(logger, s)

		logger.Infof("Listening on %s", addr)

		go utAPI.RunBackgroundTasks(ctx, logger)

		go func() {
			if err := tcpproxy.ListenAndServe(addr, utAPI); err != nil {
				logger.Errorf("tcpproxy.ListenAndServe utAPI: %v", err)
				cancel()
			}
		}()

		go func() {
			if err := tcpproxy.ListenAndServe(pAddr, utPAPI); err != nil {
				logger.Errorf("tcpproxy.ListenAndServe utPAPI: %v", err)
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

			go func() {
				for {
					utAPI.DmsgServers = dmsgDC.ConnectedServersPK()
					time.Sleep(time.Second)
				}
			}()

			go dmsghttp.UpdateServers(ctx, dClient, dmsgDisc, dmsgDC, logger)

			go func() {
				if err := dmsghttp.ListenAndServe(ctx, sk, utAPI, dClient, dmsg.DefaultDmsgHTTPPort, dmsgDC, logger); err != nil {
					logger.Errorf("dmsghttp.ListenAndServe utAPI: %v", err)
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
