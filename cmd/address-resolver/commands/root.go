// Package commands cmd/address-resolver/commands/root.go
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
	"github.com/skycoin/skywire-utilities/pkg/skyenv"
	"github.com/skycoin/skywire-utilities/pkg/storeconfig"
	"github.com/skycoin/skywire-utilities/pkg/tcpproxy"
	"github.com/spf13/cobra"
	"github.com/xtaci/kcp-go"

	"github.com/SkycoinPro/skywire-services/internal/armetrics"
	"github.com/SkycoinPro/skywire-services/pkg/address-resolver/api"
	"github.com/SkycoinPro/skywire-services/pkg/address-resolver/store"
)

const (
	statusFailure = 1
	redisPrefix   = "address-resolver"
	redisScheme   = "redis://"
)

var (
	addr            string
	metricsAddr     string
	redisURL        string
	redisPoolSize   int
	logEnabled      bool
	syslogAddr      string
	tag             string
	testing         bool
	dmsgDisc        string
	whitelistKeys   string
	testEnvironment bool
	sk              cipher.SecKey
)

func init() {
	rootCmd.Flags().StringVarP(&addr, "addr", "a", ":9093", "address to bind to")
	rootCmd.Flags().StringVarP(&metricsAddr, "metrics", "m", "", "address to bind metrics API to")
	rootCmd.Flags().StringVar(&redisURL, "redis", "redis://localhost:6379", "connections string for a redis store")
	rootCmd.Flags().IntVar(&redisPoolSize, "redis-pool-size", 10, "redis connection pool size")
	rootCmd.Flags().BoolVarP(&logEnabled, "log", "l", true, "enable request logging")
	rootCmd.Flags().StringVar(&syslogAddr, "syslog", "", "syslog server address. E.g. localhost:514")
	rootCmd.Flags().StringVar(&tag, "tag", "address_resolver", "logging tag")
	rootCmd.Flags().BoolVarP(&testing, "testing", "t", false, "enable testing to start without redis")
	rootCmd.Flags().StringVar(&dmsgDisc, "dmsg-disc", "http://dmsgd.skywire.skycoin.com", "url of dmsg-discovery")
	rootCmd.Flags().StringVar(&whitelistKeys, "whitelist-keys", "", "list of whitelisted keys of network monitor used for deregistration")
	rootCmd.Flags().BoolVar(&testEnvironment, "test-environment", false, "distinguished between prod and test environment")
	rootCmd.Flags().Var(&sk, "sk", "dmsg secret key")
}

var rootCmd = &cobra.Command{
	Use:   "address-resolver",
	Short: "Address Resolver Server for skywire",
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
			PoolSize: redisPoolSize,
		}

		if testing {
			storeConfig.Type = storeconfig.Memory
		}

		var logger *logging.Logger
		if logEnabled {
			logger = logging.MustGetLogger(tag)
		} else {
			logger = nil
		}

		ctx, cancel := cmdutil.SignalContext(context.Background(), logger)
		defer cancel()

		transportStore, err := store.New(ctx, storeConfig, logger)
		if err != nil {
			logger.Fatal("Failed to initialize redis store: ", err)
		}

		var whitelistPKs []string
		if whitelistKeys != "" {
			whitelistPKs = strings.Split(whitelistKeys, ",")
		} else {
			if testEnvironment {
				whitelistPKs = strings.Split(skyenv.TestNetworkMonitorPK, ",")
			} else {
				whitelistPKs = strings.Split(skyenv.NetworkMonitorPK, ",")
			}
		}

		for _, v := range whitelistPKs {
			api.WhitelistPKs.Set(v)
		}

		nonceStore, err := httpauth.NewNonceStore(ctx, storeConfig, redisPrefix)
		if err != nil {
			logger.Fatal("Failed to initialize redis nonce store: ", err)
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

		var m armetrics.Metrics
		if metricsAddr == "" {
			m = armetrics.NewEmpty()
		} else {
			m = armetrics.NewVictoriaMetrics()
		}

		enableMetrics := metricsAddr != ""
		arAPI := api.New(logger, transportStore, nonceStore, enableMetrics, m)

		udpListener, err := kcp.Listen(addr)
		if err != nil {
			log.Fatal("Failed to open UDP listener: ", err)
		}

		go arAPI.ListenUDP(udpListener)

		if logger != nil {
			logger.Infof("Listening on %s", addr)
		}

		go func() {
			if err := tcpproxy.ListenAndServe(addr, arAPI); err != nil {
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
				if err := dmsghttp.ListenAndServe(ctx, pk, sk, arAPI, dClient, dmsg.DefaultDmsgHTTPPort, config, dmsgDC, logger); err != nil {
					logger.Errorf("dmsghttp.ListenAndServe: %v", err)
					cancel()
				}
			}()
		}

		<-ctx.Done()

		arAPI.Close()
	},
}

// Execute executes root CLI command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)

		os.Exit(statusFailure)
	}
}
