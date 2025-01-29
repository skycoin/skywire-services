package store

import (
	"errors"

	"github.com/skycoin/skywire/pkg/skywire-utilities/pkg/storeconfig"

	"github.com/skycoin/skywire-services/internal/nm"
)

var (
	// ErrVisorSumNotFound indicates that requested visor summary is not registered.
	ErrVisorSumNotFound = errors.New("Visor summary not found")
)

// Store stores Transport metadata and generated nonce values.
type Store interface {
	TransportStore
}

// TransportStore stores Transport metadata.
type TransportStore interface {
	GetNetworkStatus() (nm.Status, error)
}

// New constructs a new Store of requested type.
func New(config storeconfig.Config) (Store, error) {
	switch config.Type {
	case storeconfig.Memory:
		return newMemoryStore(), nil
	default:
		return nil, errors.New("unknown store type")
	}
}
