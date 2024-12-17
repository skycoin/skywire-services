package vpn

import (
	"github.com/skycoin/skywire/pkg/skywire-utilities/pkg/cipher"
)

// ClientConfig is a configuration for VPN client.
type ClientConfig struct {
	ServerPK cipher.PubKey
}
