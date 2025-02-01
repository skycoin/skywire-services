// Package api pkg/network-monitor/api.go
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/sirupsen/logrus"
	"github.com/skycoin/skywire/pkg/skywire-utilities/pkg/buildinfo"
	"github.com/skycoin/skywire/pkg/skywire-utilities/pkg/cipher"
	"github.com/skycoin/skywire/pkg/skywire-utilities/pkg/httputil"
	"github.com/skycoin/skywire/pkg/skywire-utilities/pkg/logging"
	utilenv "github.com/skycoin/skywire/pkg/skywire-utilities/pkg/skyenv"
	"github.com/skycoin/skywire/pkg/transport"

	"github.com/skycoin/skywire-services/internal/nm"
	"github.com/skycoin/skywire-services/pkg/network-monitor/store"
)

// API register all the API endpoints.
// It implements a net/http.Handler.
type API struct {
	http.Handler

	sdURL     string
	arURL     string
	utURL     string
	tpdURL    string
	dmsgdURL  string
	logger    logging.Logger
	store     store.Store
	mu        sync.RWMutex
	dMu       sync.RWMutex
	startedAt time.Time

	utData map[string]bool

	nmPk           cipher.PubKey
	nmSk           cipher.SecKey
	nmSign         cipher.Sig
	batchSize      int
	whitelistedPKs map[string]bool

	deadEntries            nm.DeadEntries
	potentiallyDeadEntries nm.PotentiallyDeadEntries
	status                 nm.Status
}

// NetworkMonitorConfig is struct for Keys and Sign value of NM
type NetworkMonitorConfig struct {
	PK        cipher.PubKey
	SK        cipher.SecKey
	Sign      cipher.Sig
	BatchSize int
}

// ServicesURLs is struct for organize URL of services
type ServicesURLs struct {
	TPD   string
	DMSGD string
	SD    string
	AR    string
	UT    string
}

// HealthCheckResponse is struct of /health endpoint
type HealthCheckResponse struct {
	BuildInfo *buildinfo.Info `json:"build_info,omitempty"`
	StartedAt time.Time       `json:"started_at,omitempty"`
}

// Error is the object returned to the client when there's an error.
type Error struct {
	Error string `json:"error"`
}

// New returns a new *chi.Mux object, which can be started as a server
func New(s store.Store, logger *logging.Logger, srvURLs ServicesURLs, nmConfig NetworkMonitorConfig) *API {

	api := &API{
		sdURL:          srvURLs.SD,
		arURL:          srvURLs.AR,
		utURL:          srvURLs.UT,
		tpdURL:         srvURLs.TPD,
		dmsgdURL:       srvURLs.DMSGD,
		logger:         *logger,
		store:          s,
		startedAt:      time.Now(),
		nmPk:           nmConfig.PK,
		nmSk:           nmConfig.SK,
		nmSign:         nmConfig.Sign,
		batchSize:      nmConfig.BatchSize,
		whitelistedPKs: whitelistedPKs(),
		potentiallyDeadEntries: nm.PotentiallyDeadEntries{
			Tpd:         make(map[string]bool),
			Dmsgd:       make(map[string]bool),
			Ar:          nm.ArData{STCPR: make(map[string]bool), SUDPH: make(map[string]bool)},
			VPN:         make(map[string]bool),
			PublicVisor: make(map[string]bool),
			Skysocks:    make(map[string]bool),
		},
		deadEntries: nm.DeadEntries{
			Tpd:         []string{},
			Dmsgd:       []string{},
			Ar:          nm.ArData{STCPR: make(map[string]bool), SUDPH: make(map[string]bool)},
			VPN:         []string{},
			PublicVisor: []string{},
			Skysocks:    []string{},
		},
		status: nm.Status{LastCleaning: &nm.LastCleaningSummary{}},
	}
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(httputil.SetLoggerMiddleware(logger))
	r.Get("/status", api.getStatus)
	r.Get("/health", api.health)
	api.Handler = r

	return api
}

func (api *API) getStatus(w http.ResponseWriter, r *http.Request) {
	data, err := api.store.GetNetworkStatus()
	if err != nil {
		api.logger.WithError(err).Warnf("error getting network status")
	}
	if err := json.NewEncoder(w).Encode(data); err != nil {
		api.writeError(w, r, err)
	}
}

func (api *API) health(w http.ResponseWriter, r *http.Request) {
	info := buildinfo.Get()
	api.writeJSON(w, r, http.StatusOK, HealthCheckResponse{
		BuildInfo: info,
		StartedAt: api.startedAt,
	})
}

func (api *API) writeJSON(w http.ResponseWriter, r *http.Request, code int, object interface{}) {
	jsonObject, err := json.Marshal(object)
	if err != nil {
		api.log(r).WithError(err).Errorf("failed to encode json response")
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	_, err = w.Write(jsonObject)
	if err != nil {
		api.log(r).WithError(err).Errorf("failed to write json response")
	}
}

// ServeHTTP implements http.Handler.
func (api *API) writeError(w http.ResponseWriter, r *http.Request, err error) {
	var status int

	if err == context.DeadlineExceeded {
		status = http.StatusRequestTimeout
	}

	// we still haven't found the error
	if status == 0 {
		if _, ok := err.(*json.SyntaxError); ok {
			status = http.StatusBadRequest
		}
	}

	// we fallback to 500
	if status == 0 {
		status = http.StatusInternalServerError
	}

	if status != http.StatusNotFound {
		api.log(r).Warnf("%d: %s", status, err)
	}

	w.WriteHeader(status)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(&Error{Error: err.Error()}); err != nil {
		api.log(r).WithError(err).Warn("Failed to encode error")
	}
}

func (api *API) log(r *http.Request) logrus.FieldLogger {
	return httputil.GetLogger(r)
}

// InitDeregistrationLoop is function which runs periodic background tasks of API.
func (api *API) InitDeregistrationLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			if err := api.deregister(ctx); err != nil {
				api.logger.WithError(err).Warn("deregister routine interrupted")
			}
			if err := api.store.SetNetworkStatus(api.status); err != nil {
				api.logger.WithError(err).Warn("unable to update network status")
			}
			time.Sleep(75 * time.Second) //nolint
		}
	}
}

// deregister use as routine to deregister old/dead entries in the network
func (api *API) deregister(ctx context.Context) error {
	api.logger.Info("deregistration routine start.")
	defer api.dMu.Unlock()
	api.dMu.Lock()

	api.status.LastUpdate = time.Now().UTC()
	// get uptime tracker in each itterate
	if err := api.getUptimeTracker(ctx); err != nil {
		api.logger.WithError(err).Warn("unable to fetch UT data")
		return err
	}
	api.status.OnlineVisors = len(api.utData)

	if err := api.tpdDeregistration(ctx); err != nil {
		api.logger.WithError(err).Warn("tpd deregistration interrupted.")
	}
	time.Sleep(75 * time.Second)
	if err := api.dmsgdDeregistration(ctx); err != nil {
		api.logger.WithError(err).Warn("dmsgd deregistration interrupted.")
	}
	time.Sleep(75 * time.Second)
	if err := api.arDeregistration(ctx); err != nil {
		api.logger.WithError(err).Warn("ar deregistration interrupted.")
	}
	time.Sleep(75 * time.Second)
	if err := api.sdDeregistration(ctx); err != nil {
		api.logger.WithError(err).Warn("sd deregistration interrupted.")
	}
	api.logger.Info("deregistration routine completed.")
	return nil
}

// dmsgdDeregistration is a routine to deregister dead entries in transport discovery
func (api *API) tpdDeregistration(ctx context.Context) error {
	api.logger.Info("tpd deregistration routine start.")
	select {
	case <-ctx.Done():
		return context.DeadlineExceeded
	default:
		api.deadEntries.Tpd = []string{}
		var tpdData []*transport.Entry

		// get tpd entries
		res, err := http.Get(api.tpdURL + "/all-transports") //nolint
		if err != nil {
			api.logger.WithError(err).Errorf("unable to fetch data from tpd")
			return err
		}

		body, err := io.ReadAll(res.Body)
		if err != nil {
			api.logger.WithError(err).Errorf("unable to read data from tpd")
			return err
		}
		err = json.Unmarshal(body, &tpdData)
		if err != nil {
			api.logger.WithError(err).Errorf("unable to unmarshal data from tpd")
			return err
		}
		// check entries in tpd that are available in UT or not, based on both edges
		for _, tp := range tpdData {
			// check edge[0]
			_, online1 := api.utData[tp.Edges[0].Hex()]
			_, online2 := api.utData[tp.Edges[1].Hex()]
			if !online1 || !online2 {
				if _, ok := api.potentiallyDeadEntries.Tpd[tp.ID.String()]; ok {
					api.deadEntries.Tpd = append(api.deadEntries.Tpd, tp.ID.String())
					delete(api.potentiallyDeadEntries.Tpd, tp.ID.String())
					continue
				}
				api.potentiallyDeadEntries.Tpd[tp.ID.String()] = true
				continue
			}
			delete(api.potentiallyDeadEntries.Tpd, tp.ID.String())
		}

		// deregister entries from tpd
		if len(api.deadEntries.Tpd) > 0 {
			api.tpdDeregister(api.deadEntries.Tpd)
		}
		api.status.Transports = len(tpdData) - (len(api.deadEntries.Tpd) + len(api.potentiallyDeadEntries.Tpd))
		api.status.LastCleaning.Tpd = len(api.deadEntries.Tpd)
		logInfo := make(logrus.Fields)
		logInfo["alive"] = api.status.Transports
		logInfo["candidate"] = len(api.potentiallyDeadEntries.Tpd)
		logInfo["dead"] = len(api.deadEntries.Tpd)
		api.logger.WithFields(logInfo).Info("tpd deregistration info:")
		api.logger.Info("tpd deregistration routine completed.")
		return nil
	}
}

func (api *API) tpdDeregister(keys []string) {
	err := api.deregisterRequest(keys, fmt.Sprintf("%s/deregister", api.tpdURL), "transport-discovery")
	if err != nil {
		api.logger.Warn(err)
		return
	}
	api.logger.Info("Deregister request send to Tpd")
}

// dmsgdDeregistration is a routine to deregister dead entries in dmsg discovery
func (api *API) dmsgdDeregistration(ctx context.Context) error {
	api.logger.Info("dmsgd deregistration routine start.")
	select {
	case <-ctx.Done():
		return context.DeadlineExceeded
	default:
		api.deadEntries.Dmsgd = []string{}
		var dmsgdData []string

		// get dmsgd entries
		res, err := http.Get(api.dmsgdURL + "/dmsg-discovery/visorEntries") //nolint
		if err != nil {
			api.logger.WithError(err).Errorf("unable to fetch data from dmsgd")
			return err
		}

		body, err := io.ReadAll(res.Body)
		if err != nil {
			api.logger.WithError(err).Errorf("unable to read data from dmsgd")
			return err
		}
		err = json.Unmarshal(body, &dmsgdData)
		if err != nil {
			api.logger.WithError(err).Errorf("unable to unmarshal data from dmsgd")
			return err
		}
		// check entries in dmsgd that are available in UT or not
		for _, entry := range dmsgdData {
			_, online := api.utData[entry]
			if !online {
				if _, ok := api.potentiallyDeadEntries.Dmsgd[entry]; ok {
					api.deadEntries.Dmsgd = append(api.deadEntries.Dmsgd, entry)
					delete(api.potentiallyDeadEntries.Dmsgd, entry)
					continue
				}
				api.potentiallyDeadEntries.Dmsgd[entry] = true
				continue
			}
			delete(api.potentiallyDeadEntries.Dmsgd, entry)
		}

		// deregister entries from dmsgd
		if len(api.deadEntries.Dmsgd) > 0 {
			api.dmsgdDeregister(api.deadEntries.Dmsgd)
		}
		api.status.LastCleaning.Dmsgd = len(api.deadEntries.Dmsgd)
		logInfo := make(logrus.Fields)
		logInfo["alive"] = len(dmsgdData) - (len(api.potentiallyDeadEntries.Dmsgd) + len(api.deadEntries.Dmsgd))
		logInfo["candidate"] = len(api.potentiallyDeadEntries.Dmsgd)
		logInfo["dead"] = len(api.deadEntries.Dmsgd)
		api.logger.WithFields(logInfo).Info("dmsgd deregistration info:")
		api.logger.Info("dmsgd deregistration routine completed.")
		return nil
	}
}

func (api *API) dmsgdDeregister(keys []string) {
	err := api.deregisterRequest(keys, fmt.Sprintf("%s/deregister", api.dmsgdURL), "dmsg-discovery")
	if err != nil {
		api.logger.Warn(err)
		return
	}
	api.logger.Info("Deregister request send to Dmsgd")
}

// arDeregistration is a routine to deregister dead entries in address resolver
func (api *API) arDeregistration(ctx context.Context) error {
	api.logger.Info("ar deregistration routine start.")
	select {
	case <-ctx.Done():
		return context.DeadlineExceeded
	default:
		api.deadEntries.Ar = nm.ArData{SUDPH: map[string]bool{}, STCPR: map[string]bool{}}
		arData, err := getVisors(api.arURL)
		if err != nil {
			api.logger.WithError(err).Errorf("unable to fetch data from ar")
			return err
		}
		// check stcpr entries in ar that are available in UT or not
		for _, entry := range arData.Stcpr {
			_, online := api.utData[entry]
			if !online {
				if _, ok := api.potentiallyDeadEntries.Ar.STCPR[entry]; ok {
					api.deadEntries.Ar.STCPR[entry] = true
					delete(api.potentiallyDeadEntries.Ar.STCPR, entry)
					continue
				}
				api.potentiallyDeadEntries.Ar.STCPR[entry] = true
				continue
			}
			delete(api.potentiallyDeadEntries.Ar.STCPR, entry)
		}

		// check sudph entries in ar that are available in UT or not
		for _, entry := range arData.Sudph {
			_, online := api.utData[entry]
			if !online {
				if _, ok := api.potentiallyDeadEntries.Ar.SUDPH[entry]; ok {
					api.deadEntries.Ar.SUDPH[entry] = true
					delete(api.potentiallyDeadEntries.Ar.SUDPH, entry)
					continue
				}
				api.potentiallyDeadEntries.Ar.SUDPH[entry] = true
				continue
			}
			delete(api.potentiallyDeadEntries.Ar.SUDPH, entry)
		}

		// deregister entries from ar
		api.arDeregister(api.deadEntries.Ar)

		// store summary and print some logs
		api.status.LastCleaning.Ar = len(api.deadEntries.Ar.STCPR) + len(api.deadEntries.Ar.SUDPH)
		stpcrInfo, sudphInfo := make(logrus.Fields), make(logrus.Fields)
		stpcrInfo["alive"] = len(arData.Stcpr) - (len(api.potentiallyDeadEntries.Ar.STCPR) + len(api.deadEntries.Ar.STCPR))
		stpcrInfo["candidate"] = len(api.potentiallyDeadEntries.Ar.STCPR)
		stpcrInfo["dead"] = len(api.deadEntries.Ar.STCPR)
		sudphInfo["alive"] = len(arData.Sudph) - (len(api.potentiallyDeadEntries.Ar.SUDPH) + len(api.deadEntries.Ar.SUDPH))
		sudphInfo["candidate"] = len(api.potentiallyDeadEntries.Ar.SUDPH)
		sudphInfo["dead"] = len(api.deadEntries.Ar.SUDPH)
		api.logger.WithFields(stpcrInfo).Info("ar deregistration info on stcpr:")
		api.logger.WithFields(sudphInfo).Info("ar deregistration info on sudph:")
		api.logger.Info("ar deregistration routine completed.")
		return nil
	}
}

func (api *API) arDeregister(entries nm.ArData) {
	var deadSTCPR []string
	for entry := range entries.STCPR {
		deadSTCPR = append(deadSTCPR, entry)
	}
	if len(deadSTCPR) > 0 {
		err := api.deregisterRequest(deadSTCPR, fmt.Sprintf("%s/deregister/stcpr", api.arURL), "address resolver [stcpr]")
		if err != nil {
			api.logger.Warn(err)
		}
		api.logger.Info("deregister request send to ar for stcpr entries")
	}

	var deadSUDPH []string
	for entry := range entries.SUDPH {
		deadSUDPH = append(deadSUDPH, entry)
	}
	if len(deadSUDPH) > 0 {
		err := api.deregisterRequest(deadSUDPH, fmt.Sprintf("%s/deregister/sudph", api.arURL), "address resolver [sudph]")
		if err != nil {
			api.logger.Warn(err)
		}
		api.logger.Info("Deregister request send to ar for sudph entries")
	}
}

// sdDeregistration is a routine to deregister dead entries in service discovery (vpn, skysocks, public-visors)
func (api *API) sdDeregistration(ctx context.Context) error {
	api.logger.Info("sd deregistration routine start.")
	select {
	case <-ctx.Done():
		return context.DeadlineExceeded
	default:
		// vpn deregistration
		api.deadEntries.VPN = []string{}
		var sdData []struct {
			Address string `json:"address"`
		}
		// get vpn entries from sd
		res, err := http.Get(api.sdURL + "/api/services?type=vpn") //nolint
		if err != nil {
			api.logger.WithError(err).Errorf("unable to fetch data from sd")
			return err
		}
		body, err := io.ReadAll(res.Body)
		if err != nil {
			api.logger.WithError(err).Errorf("unable to read data from sd")
			return err
		}
		err = json.Unmarshal(body, &sdData)
		if err != nil {
			api.logger.WithError(err).Errorf("unable to unmarshal data from sd")
			return err
		}
		// check entries in vpn that are available in ut or not
		for _, entry := range sdData {
			entryKey := strings.Split(entry.Address, ":")[0]
			_, online := api.utData[entryKey]
			if !online {
				if _, ok := api.potentiallyDeadEntries.VPN[entryKey]; ok {
					api.deadEntries.VPN = append(api.deadEntries.VPN, entryKey)
					delete(api.potentiallyDeadEntries.VPN, entryKey)
					continue
				}
				api.potentiallyDeadEntries.VPN[entryKey] = true
				continue
			}
			delete(api.potentiallyDeadEntries.VPN, entryKey)
		}

		// deregister entries from vpn
		if len(api.deadEntries.VPN) > 0 {
			api.sdDeregister(api.deadEntries.VPN, "vpn")
		}
		api.status.LastCleaning.VPN = len(api.deadEntries.VPN)
		logInfo := make(logrus.Fields)
		logInfo["alive"] = len(sdData) - (len(api.potentiallyDeadEntries.VPN) + len(api.deadEntries.VPN))
		logInfo["candidate"] = len(api.potentiallyDeadEntries.VPN)
		logInfo["dead"] = len(api.deadEntries.VPN)
		api.logger.WithFields(logInfo).Info("vpn deregistration info:")

		// public visor deregistration
		api.deadEntries.PublicVisor = []string{}
		var publicVisorData []struct {
			Address string `json:"address"`
		}
		// get public visor entries from sd
		res, err = http.Get(api.sdURL + "/api/services?type=visor") //nolint
		if err != nil {
			api.logger.WithError(err).Errorf("unable to fetch data from sd")
			return err
		}
		body, err = io.ReadAll(res.Body)
		if err != nil {
			api.logger.WithError(err).Errorf("unable to read data from sd")
			return err
		}
		err = json.Unmarshal(body, &publicVisorData)
		if err != nil {
			api.logger.WithError(err).Errorf("unable to unmarshal data from sd")
			return err
		}
		// check entries in PublicVisor that are available in UT or not
		for _, entry := range publicVisorData {
			entryKey := strings.Split(entry.Address, ":")[0]
			_, online := api.utData[entryKey]
			if !online {
				if _, ok := api.potentiallyDeadEntries.PublicVisor[entryKey]; ok {
					api.deadEntries.PublicVisor = append(api.deadEntries.PublicVisor, entryKey)
					delete(api.potentiallyDeadEntries.PublicVisor, entryKey)
					continue
				}
				api.potentiallyDeadEntries.PublicVisor[entryKey] = true
				continue
			}
			delete(api.potentiallyDeadEntries.PublicVisor, entryKey)
		}

		// deregister public visor entries from sd
		if len(api.deadEntries.PublicVisor) > 0 {
			api.sdDeregister(api.deadEntries.PublicVisor, "visor")
		}
		api.status.LastCleaning.PublicVisor = len(api.deadEntries.PublicVisor)
		logInfo = make(logrus.Fields)
		logInfo["alive"] = len(publicVisorData) - (len(api.potentiallyDeadEntries.PublicVisor) + len(api.deadEntries.PublicVisor))
		logInfo["candidate"] = len(api.potentiallyDeadEntries.PublicVisor)
		logInfo["dead"] = len(api.deadEntries.PublicVisor)
		api.logger.WithFields(logInfo).Info("public visor deregistration info:")

		// skysocks deregistration
		api.deadEntries.Skysocks = []string{}
		var skysocksData []struct {
			Address string `json:"address"`
		}
		// get skysocks entries from sd
		res, err = http.Get(api.sdURL + "/api/services?type=skysocks") //nolint
		if err != nil {
			api.logger.WithError(err).Errorf("unable to fetch data from sd")
			return err
		}
		body, err = io.ReadAll(res.Body)
		if err != nil {
			api.logger.WithError(err).Errorf("unable to read data from sd")
			return err
		}
		err = json.Unmarshal(body, &skysocksData)
		if err != nil {
			api.logger.WithError(err).Errorf("unable to unmarshal data from sd")
			return err
		}
		// check entries in skysocks that are available in ut or not
		for _, entry := range skysocksData {
			entryKey := strings.Split(entry.Address, ":")[0]
			_, online := api.utData[entryKey]
			if !online {
				if _, ok := api.potentiallyDeadEntries.Skysocks[entryKey]; ok {
					api.deadEntries.Skysocks = append(api.deadEntries.Skysocks, entryKey)
					delete(api.potentiallyDeadEntries.Skysocks, entryKey)
					continue
				}
				api.potentiallyDeadEntries.Skysocks[entryKey] = true
				continue
			}
			delete(api.potentiallyDeadEntries.Skysocks, entryKey)
		}

		// deregister skysocks entries from sd
		if len(api.deadEntries.Skysocks) > 0 {
			api.sdDeregister(api.deadEntries.Skysocks, "skysocks")
		}
		api.status.LastCleaning.Skysocks = len(api.deadEntries.Skysocks)
		logInfo = make(logrus.Fields)
		logInfo["alive"] = len(skysocksData) - (len(api.potentiallyDeadEntries.Skysocks) + len(api.deadEntries.Skysocks))
		logInfo["candidate"] = len(api.potentiallyDeadEntries.Skysocks)
		logInfo["dead"] = len(api.deadEntries.Skysocks)
		api.logger.WithFields(logInfo).Info("skysocks deregistration info:")

		api.logger.Info("sd deregistration routine completed.")
		return nil
	}
}

func (api *API) sdDeregister(entries []string, sType string) {
	if len(entries) > 0 {
		err := api.deregisterRequest(entries, fmt.Sprintf("%s/services/deregister/%s", api.sdURL, sType), fmt.Sprintf("service discovery [%s]", sType))
		if err != nil {
			api.logger.Warn(err)
		}
		api.logger.Infof("deregister request send to sd for %s entries", sType)
	}
}

// deregisterRequest is dereigstration handler for all services
func (api *API) deregisterRequest(keys []string, rawReqURL, service string) error {
	reqURL, err := url.Parse(rawReqURL)
	if err != nil {
		return fmt.Errorf("Error on parsing deregistration URL : %v", err)
	}

	jsonData, err := json.Marshal(keys)
	if err != nil {
		return fmt.Errorf("Error on parsing deregistration keys : %v", err)
	}
	body := bytes.NewReader(jsonData)

	req := &http.Request{
		Method: "DELETE",
		URL:    reqURL,
		Header: map[string][]string{
			"NM-PK":   {api.nmPk.Hex()},
			"NM-Sign": {api.nmSign.Hex()},
		},
		Body: io.NopCloser(body),
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("Error on send deregistration request : %s", err)
	}
	defer res.Body.Close() //nolint

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("Error deregister keys from %s : %s", service, err)
	}

	return nil
}

type visorTransports struct {
	Sudph []string `json:"sudph"`
	Stcpr []string `json:"stcpr"`
}

func getVisors(arURL string) (visorTransports, error) {
	var arEntries visorTransports
	res, err := http.Get(arURL + "/transports") //nolint
	if err != nil {
		return arEntries, err
	}

	body, err := io.ReadAll(res.Body)

	if err != nil {
		return arEntries, err
	}
	err = json.Unmarshal(body, &arEntries)
	if err != nil {
		return arEntries, err
	}
	return arEntries, err
}

func (api *API) getUptimeTracker(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return context.DeadlineExceeded
	default:
		response := make(map[string]bool)
		res, err := http.Get(api.utURL + "/uptimes?status=on") //nolint
		if err != nil {
			return err
		}

		body, err := io.ReadAll(res.Body)
		if err != nil {
			return err
		}
		var data []uptimes
		err = json.Unmarshal(body, &data)
		if err != nil {
			return err
		}

		for _, visor := range data {
			response[visor.Key] = visor.Online
		}
		if len(response) == 0 {
			return fmt.Errorf("empty ut data fetched")
		}
		api.utData = response
		return nil
	}
}

type uptimes struct {
	Key    string `json:"key"`
	Online bool   `json:"online"`
}

func whitelistedPKs() map[string]bool {
	whitelistedPKs := make(map[string]bool)
	for _, pk := range strings.Split(utilenv.NetworkMonitorPKs, ",") {
		whitelistedPKs[pk] = true
	}
	for _, pk := range strings.Split(utilenv.TestNetworkMonitorPKs, ",") {
		whitelistedPKs[pk] = true
	}
	whitelistedPKs[utilenv.RouteSetupPKs] = true
	whitelistedPKs[utilenv.TestRouteSetupPKs] = true
	return whitelistedPKs
}
