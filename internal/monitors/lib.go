// Package monitors internal/monitors/lib.go
package monitors

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/skycoin/skywire-utilities/pkg/cipher"
)

// MonitorConfig is the structure of monitor's config
type MonitorConfig struct {
	SK                  cipher.SecKey `json:"sk,omitempty"`
	PK                  cipher.PubKey `json:"pk,omitempty"`
	DMSGUrl             string        `json:"dmsg_url,omitempty"`
	UTUrl               string        `json:"ut_url,omitempty"`
	ARUrl               string        `json:"ar_url,omitempty"`
	TPDUrl              string        `json:"tpd_url,omitempty"`
	Addr                string        `json:"addr,omitempty"`
	LogLevel            string        `json:"log_level,omitempty"`
	SleepDeregistration time.Duration `json:"sleep_deregistration,omitempty"`
}

func (c *MonitorConfig) ensureKeys() error {
	if !c.PK.Null() {
		return nil
	}
	if c.SK.Null() {
		c.PK, c.SK = cipher.GenerateKeyPair()
		return nil
	}
	var err error
	if c.PK, err = c.SK.PubKey(); err != nil {
		return err
	}
	return nil
}

// ReadConfig reads the config file without opening or writing to it
func ReadConfig(confPath string) (*MonitorConfig, error) {
	f, err := os.ReadFile(confPath) //nolint
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	raw, err := io.ReadAll(bytes.NewReader(f))
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	var conf *MonitorConfig
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&conf); err != nil {
		return nil, fmt.Errorf("failed to decode json: %w", err)
	}
	if err := conf.ensureKeys(); err != nil {
		return nil, fmt.Errorf("%v: %w", "config has invalid secret key", err)
	}
	return conf, nil
}
