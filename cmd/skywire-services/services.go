// Package main cmd/skywire-services/services.go
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	cc "github.com/ivanpirog/coloredcobra"
	"github.com/skycoin/skywire-utilities/pkg/buildinfo"
	"github.com/spf13/cobra"

	ar "github.com/skycoin/skywire-services/cmd/address-resolver/commands"
	confbs "github.com/skycoin/skywire-services/cmd/config-bootstrapper/commands"
	dmsgm "github.com/skycoin/skywire-services/cmd/dmsg-monitor/commands"
	kg "github.com/skycoin/skywire-services/cmd/keys-gen/commands"
	lc "github.com/skycoin/skywire-services/cmd/liveness-checker/commands"
	nv "github.com/skycoin/skywire-services/cmd/node-visualizer/commands"
	pvm "github.com/skycoin/skywire-services/cmd/public-visor-monitor/commands"
	rf "github.com/skycoin/skywire-services/cmd/route-finder/commands"
	se "github.com/skycoin/skywire-services/cmd/sw-env/commands"
	tpdm "github.com/skycoin/skywire-services/cmd/tpd-monitor/commands"
	tpd "github.com/skycoin/skywire-services/cmd/transport-discovery/commands"
	tps "github.com/skycoin/skywire-services/cmd/transport-setup/commands"
)

func init() {
	RootCmd.AddCommand(
		tpd.RootCmd,
		tps.RootCmd,
		tpdm.RootCmd,
		ar.RootCmd,
		rf.RootCmd,
		confbs.RootCmd,
		kg.RootCmd,
		lc.RootCmd,
		nv.RootCmd,
		pvm.RootCmd,
		se.RootCmd,
		dmsgm.RootCmd,
	)
	tpd.RootCmd.Use = "tpd"
	tps.RootCmd.Use = "tps"
	tpdm.RootCmd.Use = "tpdm"
	ar.RootCmd.Use = "ar"
	rf.RootCmd.Use = "rf"
	confbs.RootCmd.Use = "confbs"
	kg.RootCmd.Use = "kg"
	lc.RootCmd.Use = "lc"
	nv.RootCmd.Use = "nv"
	pvm.RootCmd.Use = "pvm"
	se.RootCmd.Use = "se"
	dmsgm.RootCmd.Use = "dmsgm"

	var helpflag bool
	RootCmd.SetUsageTemplate(help)
	RootCmd.PersistentFlags().BoolVarP(&helpflag, "help", "h", false, "help for skywire-services")
	RootCmd.SetHelpCommand(&cobra.Command{Hidden: true})
	RootCmd.PersistentFlags().MarkHidden("help") //nolint
	RootCmd.CompletionOptions.DisableDefaultCmd = true

}

// RootCmd contains all subcommands
var RootCmd = &cobra.Command{
	Use: func() string {
		return strings.Split(filepath.Base(strings.ReplaceAll(strings.ReplaceAll(fmt.Sprintf("%v", os.Args), "[", ""), "]", "")), " ")[0]
	}(),
	Short: "Skywire services",
	Long: `
	┌─┐┬┌─┬ ┬┬ ┬┬┬─┐┌─┐  ┌─┐┌─┐┬─┐┬  ┬┬┌─┐┌─┐┌─┐
	└─┐├┴┐└┬┘││││├┬┘├┤───└─┐├┤ ├┬┘└┐┌┘││  ├┤ └─┐
	└─┘┴ ┴ ┴ └┴┘┴┴└─└─┘  └─┘└─┘┴└─ └┘ ┴└─┘└─┘└─┘`,
	SilenceErrors:         true,
	SilenceUsage:          true,
	DisableSuggestions:    true,
	DisableFlagsInUseLine: true,
	Version:               buildinfo.Version(),
}

func main() {
	cc.Init(&cc.Config{
		RootCmd:         RootCmd,
		Headings:        cc.HiBlue + cc.Bold,
		Commands:        cc.HiBlue + cc.Bold,
		CmdShortDescr:   cc.HiBlue,
		Example:         cc.HiBlue + cc.Italic,
		ExecName:        cc.HiBlue + cc.Bold,
		Flags:           cc.HiBlue + cc.Bold,
		FlagsDescr:      cc.HiBlue,
		NoExtraNewlines: true,
		NoBottomNewline: true,
	})
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
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
