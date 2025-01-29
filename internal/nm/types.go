// Package nm internal/nm/types.go
package nm

import "time"

// Status of network
type Status struct {
	LastUpdate   time.Time            `json:"last_update"`
	OnlineVisors int                  `json:"online_visors"`
	Transports   *TransportsSummary   `json:"transports"`
	VPN          int                  `json:"vpn"`
	Skysocks     int                  `json:"skysocks"`
	PublicVisor  int                  `json:"public_visor"`
	LastCleaning *LastCleaningSummary `json:"last_cleaning"`
}

// TransportsSummary return summary of all transports available in network
type TransportsSummary struct {
	AllTranports int `json:"all_transports"`
	Dmsg         int `json:"dmsg"`
	Stcpr        int `json:"stcpr"`
	Sudph        int `json:"sudph"`
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
