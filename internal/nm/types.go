// Package nm internal/nm/types.go
package nm

import "time"

// Status of network
type Status struct {
	LastUpdate   time.Time            `json:"last_update"`
	OnlineVisors int                  `json:"online_visors"`
	Transports   int                  `json:"transports"`
	VPN          int                  `json:"vpn"`
	Skysocks     int                  `json:"skysocks"`
	PublicVisor  int                  `json:"public_visor"`
	LastCleaning *LastCleaningSummary `json:"last_cleaning"`
}

// LastCleaningSummary return a brief summary on last itterate of network monitor and cleaning dead entries
type LastCleaningSummary struct {
	AllDeadEntriesCleaned int `json:"all_dead_entries_cleaned"`
	Tpd                   int `json:"transport_discovery"`
	Ar                    int `json:"address_resolver"`
	Dmsgd                 int `json:"dmsg_discovery"`
	VPN                   int `json:"vpn"`
	Skysocks              int `json:"skysocks"`
	PublicVisor           int `json:"public_visor"`
}

// PotentiallyDeadEntries list of potentially dead entries
type PotentiallyDeadEntries struct {
	Tpd         map[string]bool `json:"tpd"`
	Dmsgd       map[string]bool `json:"dmsgd"`
	Ar          ArData          `json:"ar"`
	VPN         map[string]bool `json:"vpn"`
	Skysocks    map[string]bool `json:"skysocks"`
	PublicVisor map[string]bool `json:"public_visor"`
}

// DeadEntries list of dead entries
type DeadEntries struct {
	Tpd         []string `json:"tpd"`
	Dmsgd       []string `json:"dmsgd"`
	Ar          ArData   `json:"ar"`
	VPN         []string `json:"vpn"`
	Skysocks    []string `json:"skysocks"`
	PublicVisor []string `json:"public_visor"`
}

type ArData struct {
	SUDPH map[string]bool `json:"sudph"`
	STCPR map[string]bool `json:"stpcr"`
}
