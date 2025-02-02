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

	cleaningDelay          time.Duration
	liveEntries            map[string]int
	deadEntries            map[string][]string
	potentiallyDeadEntries map[string]map[string]bool
	status                 nm.Status
}

// NetworkMonitorConfig is struct for Keys and Sign value of NM
type NetworkMonitorConfig struct {
	CleaningDelay int
	PK            cipher.PubKey
	SK            cipher.SecKey
	Sign          cipher.Sig
	BatchSize     int
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

var services = [4]string{"tpd", "dmsgd", "ar", "sd"}
var sdSubServices = [3]string{"vpn", "visor", "skysocks"}
var arSubServices = [2]string{"sudph", "stcpr"}

// New returns a new *chi.Mux object, which can be started as a server
func New(s store.Store, logger *logging.Logger, srvURLs ServicesURLs, nmConfig NetworkMonitorConfig) *API {

	api := &API{
		sdURL:                  srvURLs.SD,
		arURL:                  srvURLs.AR,
		utURL:                  srvURLs.UT,
		tpdURL:                 srvURLs.TPD,
		dmsgdURL:               srvURLs.DMSGD,
		logger:                 *logger,
		store:                  s,
		startedAt:              time.Now(),
		nmPk:                   nmConfig.PK,
		nmSk:                   nmConfig.SK,
		nmSign:                 nmConfig.Sign,
		batchSize:              nmConfig.BatchSize,
		whitelistedPKs:         whitelistedPKs(),
		potentiallyDeadEntries: make(map[string]map[string]bool),
		deadEntries:            make(map[string][]string),
		liveEntries:            make(map[string]int),
		status:                 nm.Status{LastCleaning: &nm.LastCleaningSummary{}},
		cleaningDelay:          time.Duration(nmConfig.CleaningDelay) * time.Second,
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

// InitCleaningLoop is function which runs periodic background tasks of API.
func (api *API) InitCleaningLoop(ctx context.Context) {
	api.initCleaning()
	for {
		select {
		case <-ctx.Done():
			return
		default:
			if err := api.cleaning(ctx); err != nil {
				api.logger.WithError(err).Warn("cleaning routine interrupted")
			}
			if err := api.storeNetworkStatus(); err != nil {
				api.logger.WithError(err).Warn("unable to update network status")
			}
			time.Sleep(api.cleaningDelay)
		}
	}
}

func (api *API) storeNetworkStatus() error {
	// alive info
	api.status.Transports = api.liveEntries["tpd"]
	api.status.VPN = api.liveEntries["vpn"]
	api.status.PublicVisor = api.liveEntries["visor"]
	api.status.Skysocks = api.liveEntries["skysocks"]

	// last cleaning info
	api.status.LastCleaning.Dmsgd = len(api.deadEntries["dmsgd"])
	api.status.LastCleaning.Tpd = len(api.deadEntries["tpd"])
	api.status.LastCleaning.Ar.SUDPH = len(api.deadEntries["sudph"])
	api.status.LastCleaning.Ar.STCPR = len(api.deadEntries["stcpr"])
	api.status.LastCleaning.VPN = len(api.deadEntries["vpn"])
	api.status.LastCleaning.PublicVisor = len(api.deadEntries["visor"])
	api.status.LastCleaning.Skysocks = len(api.deadEntries["skysocks"])
	for _, service := range api.deadEntries {
		api.status.LastCleaning.AllDeadEntriesCleaned += len(service)
	}

	return api.store.SetNetworkStatus(api.status)
}

func (api *API) initCleaning() {
	for _, service := range services {
		if service != "ar" && service != "sd" {
			api.potentiallyDeadEntries[service] = make(map[string]bool)
		}
	}
	for _, subService := range sdSubServices {
		api.potentiallyDeadEntries[subService] = make(map[string]bool)
	}
	for _, subService := range arSubServices {
		api.potentiallyDeadEntries[subService] = make(map[string]bool)
	}
}

// cleaning use as routine to cleaning old/dead entries in the network
func (api *API) cleaning(ctx context.Context) error {
	api.logger.Info("cleaning routine start.")
	defer api.dMu.Unlock()
	api.dMu.Lock()

	api.status.LastUpdate = time.Now().UTC()
	// get uptime tracker in each itterate
	if err := api.getUptimeTracker(ctx); err != nil {
		api.logger.WithError(err).Warn("unable to fetch UT data")
		return err
	}
	// cleaning services
	for _, service := range services {
		api.clean(ctx, service)
		time.Sleep(api.cleaningDelay)
	}
	api.logger.Info("cleaning routine done.")
	return nil
}

func (api *API) clean(ctx context.Context, service string) {
	api.logger.Infof("%s cleaning process start.", service)
	switch service {
	case "tpd":
		api.deadEntries[service] = []string{}
		if err := api.tpdCleaning(ctx); err != nil {
			api.logger.WithError(err).Warnf("%s cleaning interrupted.", service)
		}
	case "dmsgd":
		api.deadEntries[service] = []string{}
		if err := api.cleaningService(ctx, service, ""); err != nil {
			api.logger.WithError(err).Warnf("%s cleaning interrupted.", service)
		}
	case "ar":
		for _, sub := range arSubServices {
			api.deadEntries[sub] = []string{}
			if err := api.cleaningService(ctx, service, sub); err != nil {
				api.logger.WithError(err).Warnf("%s cleaning interrupted.", service)
			}
		}
	case "sd":
		for _, sub := range sdSubServices {
			api.deadEntries[sub] = []string{}
			if err := api.cleaningService(ctx, service, sub); err != nil {
				api.logger.WithError(err).Warnf("%s cleaning interrupted.", service)
			}
		}
	}
	api.logger.Infof("%s cleaning process done.", service)
}

func (api *API) cleaningService(ctx context.Context, service, sType string) error {
	var data []string
	var err error
	var target string
	switch service {
	case "dmsgd":
		data, err = api.fetchDmsgdData(ctx)
		target = service
	case "ar":
		data, err = api.fetchArData(ctx, sType)
		target = sType
	default:
		data, err = api.fetchSdData(ctx, sType)
		target = sType
	}
	if err != nil {
		api.logger.WithError(err).Warnf("unable to fetch data from %s", service)
		return err
	}

	if err := api.checkingEntries(ctx, data, service, sType); err != nil {
		api.logger.WithError(err).Errorf("unable to checking data from %s", service)
		return err
	}
	if len(api.deadEntries[target]) > 0 {
		if err := api.deregister(api.deadEntries[target], service, sType); err != nil {
			api.logger.WithError(err).Errorf("unable to deregister dead entries from %s", service)
		}
	}
	// logs
	if err := api.cleaningInfo(ctx, service, sType); err != nil {
		api.logger.WithError(err).Warn("unable to show cleaning info")
	}
	return err

}

func (api *API) fetchSdData(ctx context.Context, sType string) ([]string, error) {
	var data []string
	select {
	case <-ctx.Done():
		return data, context.DeadlineExceeded
	default:
		var sdData []struct {
			Address string `json:"address"`
		}
		res, err := http.Get(fmt.Sprintf("%s/api/services?type=%s", api.sdURL, sType)) //nolint
		if err != nil {
			api.logger.WithError(err).Errorf("unable to fetch data from sd")
			return data, err
		}
		body, err := io.ReadAll(res.Body)
		if err != nil {
			api.logger.WithError(err).Errorf("unable to read data from sd")
			return data, err
		}
		err = json.Unmarshal(body, &sdData)
		if err != nil {
			api.logger.WithError(err).Errorf("unable to unmarshal data from sd")
			return data, err
		}
		// check entries in vpn that are available in ut or not
		for _, entry := range sdData {
			data = append(data, strings.Split(entry.Address, ":")[0])
		}
		return data, nil
	}
}
func (api *API) fetchArData(ctx context.Context, sType string) ([]string, error) {
	var data []string
	select {
	case <-ctx.Done():
		return data, context.DeadlineExceeded
	default:
		// Fetch Data from AR
		var arEntries visorTransports
		res, err := http.Get(api.arURL + "/transports") //nolint
		if err != nil {
			return data, err
		}

		body, err := io.ReadAll(res.Body)

		if err != nil {
			return data, err
		}
		err = json.Unmarshal(body, &arEntries)
		if err != nil {
			return data, err
		}
		data = arEntries.Stcpr
		if sType == "sudph" {
			data = arEntries.Sudph
		}
		return data, nil
	}
}
func (api *API) fetchDmsgdData(ctx context.Context) ([]string, error) {
	var data []string
	select {
	case <-ctx.Done():
		return data, context.DeadlineExceeded
	default:
		// get dmsgd entries
		res, err := http.Get(api.dmsgdURL + "/dmsg-discovery/visorEntries") //nolint
		if err != nil {
			api.logger.WithError(err).Errorf("unable to fetch data from dmsgd")
			return data, err
		}

		body, err := io.ReadAll(res.Body)
		if err != nil {
			api.logger.WithError(err).Errorf("unable to read data from dmsgd")
			return data, err
		}
		err = json.Unmarshal(body, &data)
		if err != nil {
			api.logger.WithError(err).Errorf("unable to unmarshal data from dmsgd")
			return data, err
		}
		return data, nil
	}
}

func (api *API) checkingEntries(ctx context.Context, data []string, service, sType string) error {
	target := service
	if sType != "" {
		target = sType
	}
	select {
	case <-ctx.Done():
		return context.DeadlineExceeded
	default:
		for _, entry := range data {
			_, online := api.utData[entry]
			if !online {
				if _, ok := api.potentiallyDeadEntries[target][entry]; ok {
					api.deadEntries[target] = append(api.deadEntries[target], entry)
					delete(api.potentiallyDeadEntries[target], entry)
					continue
				}
				api.potentiallyDeadEntries[target][entry] = true
				continue
			}
			delete(api.potentiallyDeadEntries[target], entry)
		}
		api.liveEntries[target] = len(data) - (len(api.potentiallyDeadEntries[service]) + len(api.deadEntries[service]))
		return nil
	}
}

func (api *API) cleaningInfo(ctx context.Context, service, sType string) error {
	if sType != "" {
		service = sType
	}
	select {
	case <-ctx.Done():
		return context.DeadlineExceeded
	default:
		logInfo := make(logrus.Fields)
		logInfo["alive"] = api.liveEntries[service]
		logInfo["candidate"] = len(api.potentiallyDeadEntries[service])
		logInfo["dead"] = len(api.deadEntries[service])
		api.logger.WithFields(logInfo).Infof("%s cleaning info:", service)
		return nil
	}
}

// tpdCleaning is a routine to clean dead entries in transport discovery
func (api *API) tpdCleaning(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return context.DeadlineExceeded
	default:
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
				if _, ok := api.potentiallyDeadEntries["tpd"][tp.ID.String()]; ok {
					api.deadEntries["tpd"] = append(api.deadEntries["tpd"], tp.ID.String())
					delete(api.potentiallyDeadEntries["tpd"], tp.ID.String())
					continue
				}
				api.potentiallyDeadEntries["tpd"][tp.ID.String()] = true
				continue
			}
			delete(api.potentiallyDeadEntries["tpd"], tp.ID.String())
		}

		// deregister entries from tpd
		if len(api.deadEntries["tpd"]) > 0 {
			if err := api.deregister(api.deadEntries["tpd"], "tpd", ""); err != nil {
				api.logger.WithError(err).Errorf("unable to deregister dead entries from %s", "tpd")
			}
		}

		api.liveEntries["tpd"] = len(tpdData) - (len(api.deadEntries["tpd"]) + len(api.potentiallyDeadEntries["tpd"]))
		logInfo := make(logrus.Fields)
		logInfo["alive"] = api.liveEntries["tpd"]
		logInfo["candidate"] = len(api.potentiallyDeadEntries["tpd"])
		logInfo["dead"] = len(api.deadEntries["tpd"])
		api.logger.WithFields(logInfo).Info("tpd deregistration info:")
		return nil
	}
}

func (api *API) deregister(entries []string, service, sType string) error {
	var err error
	switch service {
	case "tpd":
		err = api.deregisterRequest(entries, fmt.Sprintf("%s/deregister", api.tpdURL), service)
	case "dmsgd":
		err = api.deregisterRequest(entries, fmt.Sprintf("%s/deregister", api.dmsgdURL), service)
	case "ar":
		err = api.deregisterRequest(entries, fmt.Sprintf("%s/deregister/%s", api.arURL, sType), fmt.Sprintf("%s [%s]", service, sType))
	case "sd":
		err = api.deregisterRequest(entries, fmt.Sprintf("%s/api/services/deregister/%s", api.sdURL, sType), fmt.Sprintf("%s [%s]", service, sType))
	}
	if err != nil {
		return err
	}
	api.logger.Infof("deregister request send to sd for %s entries", sType)
	return nil
}

// deregisterRequest is dereigstration handler for all services
func (api *API) deregisterRequest(keys []string, rawReqURL, service string) error {
	reqURL, err := url.Parse(rawReqURL)
	if err != nil {
		return fmt.Errorf("error on parsing deregistration URL : %v", err)
	}

	jsonData, err := json.Marshal(keys)
	if err != nil {
		return fmt.Errorf("error on marshaling deregistration keys : %v", err)
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
		return fmt.Errorf("error on send deregistration request : %s", err)
	}
	defer res.Body.Close() //nolint

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("error on deregister keys from %s : %s", service, err)
	}

	return nil
}

type visorTransports struct {
	Sudph []string `json:"sudph"`
	Stcpr []string `json:"stcpr"`
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
		api.status.OnlineVisors = len(response)
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
