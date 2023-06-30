// Package commands cmd/vpn-monitor/commands/root.go
package commands

import (
	"context"
	"log"
	"os"
	"time"

	cc "github.com/ivanpirog/coloredcobra"
	"github.com/skycoin/skywire-utilities/pkg/buildinfo"
	"github.com/skycoin/skywire-utilities/pkg/cipher"
	"github.com/skycoin/skywire-utilities/pkg/cmdutil"
	"github.com/skycoin/skywire-utilities/pkg/logging"
	utilenv "github.com/skycoin/skywire-utilities/pkg/skyenv"
	"github.com/skycoin/skywire-utilities/pkg/tcpproxy"
	"github.com/skycoin/skywire/pkg/app/appserver"
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
	rootCmd.Flags().StringVarP(&addr, "addr", "a", ":9081", "address to bind to.\033[0m")
	rootCmd.Flags().DurationVarP(&sleepDeregistration, "sleep-deregistration", "s", 10, "Sleep time for derigstration process in minutes\033[0m")
	rootCmd.Flags().StringVarP(&confPath, "config", "c", "vpn-monitor.json", "config file location.\033[0m")
	rootCmd.Flags().StringVar(&tag, "tag", "vpn_monitor", "logging tag\033[0m")
	var helpflag bool
	rootCmd.SetUsageTemplate(help)
	rootCmd.PersistentFlags().BoolVarP(&helpflag, "help", "h", false, "help for "+rootCmd.Use)
	rootCmd.SetHelpCommand(&cobra.Command{Hidden: true})
	rootCmd.PersistentFlags().MarkHidden("help") //nolint
}

var rootCmd = &cobra.Command{
	Use:   "vpn-monitor",
	Short: "VPN monitor.",
	Long: `
	┬  ┬┌─┐┌┐┌   ┌┬┐┌─┐┌┐┌┬┌┬┐┌─┐┬─┐
	└┐┌┘├─┘│││───││││ │││││ │ │ │├┬┘
	 └┘ ┴  ┘└┘   ┴ ┴└─┘┘└┘┴ ┴ └─┘┴└─`,
	SilenceErrors:         true,
	SilenceUsage:          true,
	DisableSuggestions:    true,
	DisableFlagsInUseLine: true,
	Version:               buildinfo.Version(),
	Run: func(_ *cobra.Command, _ []string) {
		visorBuildInfo := buildinfo.Get()
		if _, err := visorBuildInfo.WriteTo(os.Stdout); err != nil {
			log.Printf("Failed to output build info: %v", err)
		}

		mLogger := logging.NewMasterLogger()
		conf := initConfig(confPath, mLogger)

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
}

func initConfig(confPath string, mLog *logging.MasterLogger) *visorconfig.V1 {
	log := mLog.PackageLogger("network_monitor:config")
	log.Info("Reading config from file.")
	log.WithField("filepath", confPath).Info()

	oldConf, err := visorconfig.ReadFile(confPath)
	if err != nil {
		log.WithError(err).Fatal("Failed to read config file.")
	}
	var testEnv bool
	if oldConf.Dmsg.Discovery == utilenv.TestDmsgDiscAddr {
		testEnv = true
	}
	// have same services as old config
	services := &visorconfig.Services{
		DmsgDiscovery:      oldConf.Dmsg.Discovery,
		TransportDiscovery: oldConf.Transport.Discovery,
		AddressResolver:    oldConf.Transport.AddressResolver,
		RouteFinder:        oldConf.Routing.RouteFinder,
		RouteSetupNodes:    oldConf.Routing.RouteSetupNodes,
		UptimeTracker:      oldConf.UptimeTracker.Addr,
		ServiceDiscovery:   oldConf.Launcher.ServiceDisc,
	}
	// update old config
	conf, err := visorconfig.MakeDefaultConfig(mLog, &oldConf.SK, false, false, testEnv, false, false, confPath, "", services)
	if err != nil {
		log.WithError(err).Fatal("Failed to create config.")
	}

	// have the same apps that the old config had
	var newConfLauncherApps []appserver.AppConfig
	for _, app := range conf.Launcher.Apps {
		for _, oldApp := range oldConf.Launcher.Apps {
			if app.Name == oldApp.Name {
				newConfLauncherApps = append(newConfLauncherApps, app)
			}
		}
	}
	conf.Launcher.Apps = newConfLauncherApps

	conf.Version = oldConf.Version
	conf.LocalPath = oldConf.LocalPath
	conf.Launcher.BinPath = oldConf.Launcher.BinPath
	conf.Launcher.ServerAddr = oldConf.Launcher.ServerAddr
	conf.CLIAddr = oldConf.CLIAddr

	// following services are not needed
	conf.STCP = nil
	conf.Dmsgpty = nil
	conf.Transport.PublicAutoconnect = false

	// save the config file
	if err := conf.Flush(); err != nil {
		log.WithError(err).Fatal("Failed to flush config to file.")
	}

	return conf
}

// Execute executes root CLI command.
func Execute() {
	cc.Init(&cc.Config{
		RootCmd:       rootCmd,
		Headings:      cc.HiBlue + cc.Bold, //+ cc.Underline,
		Commands:      cc.HiBlue + cc.Bold,
		CmdShortDescr: cc.HiBlue,
		Example:       cc.HiBlue + cc.Italic,
		ExecName:      cc.HiBlue + cc.Bold,
		Flags:         cc.HiBlue + cc.Bold,
		//FlagsDataType: cc.HiBlue,
		FlagsDescr:      cc.HiBlue,
		NoExtraNewlines: true,
		NoBottomNewline: true,
	})
	if err := rootCmd.Execute(); err != nil {
		log.Fatal("Failed to execute command: ", err)
	}
}

const help = "Usage:\r\n" +
	"  {{.UseLine}}{{if .HasAvailableSubCommands}}{{end}} {{if gt (len .Aliases) 0}}\r\n\r\n" +
	"{{.NameAndAliases}}{{end}}{{if .HasAvailableSubCommands}}\r\n\r\n" +
	"Available Commands:{{range .Commands}}{{if (or .IsAvailableCommand)}}\r\n  " +
	"{{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}\r\n\r\n" +
	"Flags:\r\n" +
	"{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}\r\n\r\n" +
	"Global Flags:\r\n" +
	"{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}\r\n\r\n"
