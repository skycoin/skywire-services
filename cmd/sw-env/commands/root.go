// Package commands cmd/sw-env/commands/root.go
package commands

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"

	cfg "github.com/SkycoinPro/skywire-services/internal/config"
)

var rootCmd = &cobra.Command{
	Use:   "sw-env",
	Short: "skywire environment generator",
	Run: func(_ *cobra.Command, _ []string) {
		switch {
		case publicFlag:
			fmt.Println(cfg.PrintJSON(cfg.DefaultPublicEnv()))
		case localFlag:
			fmt.Println(cfg.PrintJSON(cfg.DefaultLocalEnv()))
		case dockerFlag:
			fmt.Println(cfg.PrintJSON(cfg.DefaultDockerizedEnv(dockerNetwork)))
		}
	},
}

var (
	publicFlag    bool
	localFlag     bool
	dockerFlag    bool
	dockerNetwork string
)

func init() {
	rootCmd.AddCommand(
		visorCmd,
		dmsgCmd,
		setupCmd,
	)
	rootCmd.Flags().BoolVarP(&publicFlag, "public", "p", false, "Environment with public skywire-services")
	rootCmd.Flags().BoolVarP(&localFlag, "local", "l", false, "Environment with skywire-services on localhost")
	rootCmd.Flags().BoolVarP(&dockerFlag, "docker", "d", false, "Environment with dockerized skywire-services")
	rootCmd.Flags().StringVarP(&dockerNetwork, "network", "n", "SKYNET", "Docker network to use")
}

var visorCmd = &cobra.Command{
	Use:   "visor",
	Short: "Generate config for skywire-visor",
	Run: func(_ *cobra.Command, _ []string) {
		fmt.Println(cfg.PrintJSON(cfg.DefaultPublicVisorConfig()))
	},
}

var dmsgCmd = &cobra.Command{
	Use:   "dmsg",
	Short: "Generate config for dmsg-server",
	Run: func(_ *cobra.Command, _ []string) {
		fmt.Println(cfg.PrintJSON(cfg.EmptyDmsgServerConfig()))
	},
}

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Generate config for setup node",
	Run: func(_ *cobra.Command, _ []string) {
		fmt.Println(cfg.PrintJSON(cfg.EmptySetupNodeConfig()))
	},
}

// Execute executes root CLI command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
