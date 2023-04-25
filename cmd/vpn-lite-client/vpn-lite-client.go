// Package main cmd/vpn-lite-client/vpn-lite-client.go
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/skycoin/skywire-utilities/pkg/cipher"
	"github.com/skycoin/skywire/pkg/app"
	"github.com/skycoin/skywire/pkg/app/appevent"
	"github.com/skycoin/skywire/pkg/app/appserver"

	"github.com/SkycoinPro/skywire-services/internal/vpn"
)

var (
	serverPKStr = flag.String("srv", "", "PubKey of the server to connect to")
)

func main() {
	flag.Parse()

	eventSub := appevent.NewSubscriber()

	appCl := app.NewClient(eventSub)
	defer appCl.Close()

	if *serverPKStr == "" {
		err := errors.New("VPN server pub key is missing")
		print(fmt.Sprintf("%v\n", err))
		setAppErr(appCl, err)
		os.Exit(1)
	}

	serverPK := cipher.PubKey{}
	if err := serverPK.UnmarshalText([]byte(*serverPKStr)); err != nil {
		print(fmt.Sprintf("Invalid local SK: %v\n", err))
		setAppErr(appCl, err)
		os.Exit(1)
	}

	fmt.Printf("Connecting to VPN server %s\n", serverPK.String())

	vpnLiteClientCfg := vpn.ClientConfig{
		ServerPK: serverPK,
	}
	vpnLiteClient, err := vpn.NewLiteClient(vpnLiteClientCfg, appCl)
	if err != nil {
		print(fmt.Sprintf("Error creating VPN lite client: %v\n", err))
		setAppErr(appCl, err)
	}

	osSigs := make(chan os.Signal, 2)
	sigs := []os.Signal{syscall.SIGTERM, syscall.SIGINT}
	for _, sig := range sigs {
		signal.Notify(osSigs, sig)
	}

	go func() {
		<-osSigs
		vpnLiteClient.Close()
	}()

	defer setAppStatus(appCl, appserver.AppDetailedStatusStopped)

	if err := vpnLiteClient.Serve(); err != nil {
		print(fmt.Sprintf("Failed to serve VPN lite client: %v\n", err))
	}

}

func setAppErr(appCl *app.Client, err error) {
	if appErr := appCl.SetError(err.Error()); appErr != nil {
		print(fmt.Sprintf("Failed to set error %v: %v\n", err, appErr))
	}
}

func setAppStatus(appCl *app.Client, status appserver.AppDetailedStatus) {
	if err := appCl.SetDetailedStatus(string(status)); err != nil {
		print(fmt.Sprintf("Failed to set status %v: %v\n", status, err))
	}
}
