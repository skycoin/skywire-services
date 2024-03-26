// Package api pkg/network-monitor/api.go
package api

import (
	"bytes"
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
	"github.com/skycoin/skywire-utilities/pkg/buildinfo"
	"github.com/skycoin/skywire-utilities/pkg/cipher"
	"github.com/skycoin/skywire-utilities/pkg/httputil"
	"github.com/skycoin/skywire-utilities/pkg/logging"
	utilenv "github.com/skycoin/skywire-utilities/pkg/skyenv"
)

// API register all the API endpoints.
// It implements a net/http.Handler.
type API struct {
	http.Handler

	dmsgURL   string
	utURL     string
	arURL     string
	logger    logging.Logger
	dMu       sync.RWMutex
	startedAt time.Time

	nmPk           cipher.PubKey
	nmSign         cipher.Sig
	whitelistedPKs map[string]bool
}

// MonitorConfig is struct for Keys and Sign value of network monitor
type MonitorConfig struct {
	PK   cipher.PubKey
	Sign cipher.Sig
	DMSG string
	UT   string
	AR   string
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
func New(logger *logging.Logger, monitorConfig MonitorConfig) *API {

	api := &API{
		logger:         *logger,
		startedAt:      time.Now(),
		nmPk:           monitorConfig.PK,
		nmSign:         monitorConfig.Sign,
		dmsgURL:        monitorConfig.DMSG,
		utURL:          monitorConfig.UT,
		arURL:          monitorConfig.AR,
		whitelistedPKs: whitelistedPKs(),
	}
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(httputil.SetLoggerMiddleware(logger))
	r.Get("/health", api.health)
	api.Handler = r

	return api
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

func (api *API) log(r *http.Request) logrus.FieldLogger {
	return httputil.GetLogger(r)
}

// InitDeregistrationLoop is function which runs periodic background tasks of API.
func (api *API) InitDeregistrationLoop(sleepDeregistration time.Duration) {
	deadDmsgCandidate := make(map[string]bool)
	deadStcprCandidate := make(map[string]bool)
	deadSudphCandidate := make(map[string]bool)
	for {
		api.deregister(deadDmsgCandidate, deadStcprCandidate, deadSudphCandidate)
		time.Sleep(sleepDeregistration * time.Minute)
	}
}

// deregister use as routine to deregister old/dead entries in the network
func (api *API) deregister(deadDmsgCandidate, deadStcprCandidate, deadSudphCandidate map[string]bool) {
	api.logger.Info("Deregistration routine started.")
	defer api.dMu.Unlock()
	api.dMu.Lock()

	// get uptimes data to check online/offline of visor based on uptime tracker
	uptimes, err := getUptimeTracker(api.utURL)
	if err != nil {
		api.logger.Warnf("Error occur during get uptime tracker status list due to %s", err)
		return
	}

	api.networkDeregistration(deadDmsgCandidate, deadStcprCandidate, deadSudphCandidate, uptimes)

	api.logger.Info("Deregistration routine completed.")
}

// dmsgDeregistration is a routine to deregister dead dmsg entries in dmsg discovery
func (api *API) networkDeregistration(deadDmsgCandidate, deadStcprCandidate, deadSudphCandidate, uptimes map[string]bool) {
	conf := checkerConfig{
		wg:      new(sync.WaitGroup),
		locker:  new(sync.Mutex),
		uptimes: uptimes,
	}
	api.dmsgDeregistration(conf, deadDmsgCandidate)
	api.arDeregistration(conf, deadStcprCandidate, deadSudphCandidate)
}

func (api *API) dmsgDeregistration(conf checkerConfig, deadDmsgCandidate map[string]bool) {
	api.logger.Info("DMSG deregistraion routine started.")
	// get list of all dmsg clients, not servers
	dmsgEntries, err := getDMSGEntries(api.dmsgURL)
	if err != nil {
		api.logger.Warnf("Error occur during get dmsg entries list due to %s", err)
		return
	}

	// DMSG deregistration
	deadDmsg := []string{}
	for _, entry := range dmsgEntries {
		if _, ok := api.whitelistedPKs[entry]; !ok {
			conf.wg.Add(1)
			conf.entry = entry
			go api.entryChecker(conf, deadDmsgCandidate, &deadDmsg)
		}
	}
	conf.wg.Wait()
	if len(deadDmsg) > 0 {
		api.dmsgDeregister(deadDmsg)
	}
	api.logger.WithField("List of dead DMSG entries", deadDmsg).WithField("Number of dead DMSG entries", len(deadDmsg)).Info("DMSGD Deregistration completed.")
	api.logger.Info("DMSG deregistraion routine completed.")
}

func (api *API) arDeregistration(conf checkerConfig, deadStcprCandidate, deadSudphCandidate map[string]bool) {
	api.logger.Info("AR deregistraion routine started.")
	// get list of all ar entries
	arEntries, err := getAREntries(api.arURL)
	if err != nil {
		api.logger.Warnf("error occur during get ar entries list due to %s", err)
		return
	}

	// STCPR deregistration
	deadStcpr := []string{}
	for _, entry := range arEntries.Stcpr {
		if _, ok := api.whitelistedPKs[entry]; !ok {
			conf.wg.Add(1)
			conf.entry = entry
			go api.entryChecker(conf, deadStcprCandidate, &deadStcpr)
		}
	}
	conf.wg.Wait()
	if len(deadStcpr) > 0 {
		api.arDeregister(deadStcpr, "stcpr")
	}
	api.logger.WithField("list of dead stcpr entries", deadStcpr).WithField("number of dead stcpr entries", len(deadStcpr)).Info("stcpr deregistration completed.")

	// SUDPH deregistration
	deadSudph := []string{}
	for _, entry := range arEntries.Sudph {
		if _, ok := api.whitelistedPKs[entry]; !ok {
			conf.wg.Add(1)
			conf.entry = entry
			go api.entryChecker(conf, deadSudphCandidate, &deadSudph)
		}
	}
	conf.wg.Wait()
	if len(deadSudph) > 0 {
		api.arDeregister(deadSudph, "sudph")
	}
	api.logger.WithField("list of dead sudph entries", deadSudph).WithField("number of dead sudph entries", len(deadSudph)).Info("sudph deregistration completed.")
	api.logger.Info("AR deregistraion routine completed.")
}

func (api *API) entryChecker(cfg checkerConfig, deadCandidate map[string]bool, deadEntries *[]string) {
	defer cfg.wg.Done()

	key := cipher.PubKey{}
	err := key.UnmarshalText([]byte(cfg.entry))
	if err != nil {
		api.logger.Warnf("Error marshaling key: %s", err)
		return
	}

	if status, ok := cfg.uptimes[key.Hex()]; !ok || !status {
		cfg.locker.Lock()
		if _, ok := deadCandidate[key.Hex()]; ok {
			*deadEntries = append(*deadEntries, key.Hex())
			delete(deadCandidate, key.Hex())
		} else {
			deadCandidate[key.Hex()] = true
		}
		cfg.locker.Unlock()
	}
}

func (api *API) dmsgDeregister(keys []string) {
	err := api.deregisterRequest(keys, api.dmsgURL+"/dmsg-discovery/deregister", "dmsg discovery")
	if err != nil {
		api.logger.Warn(err)
		return
	}
	api.logger.Info("Deregister request send to DSMGD")
}

func (api *API) arDeregister(keys []string, entryType string) {
	err := api.deregisterRequest(keys, fmt.Sprintf(api.arURL+"/deregister/%s", entryType), "address resolver")
	if err != nil {
		api.logger.Warn(err)
		return
	}
	api.logger.Info("Deregister request send to DSMGD")
}

type checkerConfig struct {
	entry   string
	uptimes map[string]bool
	wg      *sync.WaitGroup
	locker  *sync.Mutex
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

type clientList []string

func getDMSGEntries(dmsgURL string) (data clientList, err error) {
	res, err := http.Get(dmsgURL + "/dmsg-discovery/visorEntries") //nolint

	if err != nil {
		return nil, err
	}

	body, err := io.ReadAll(res.Body)

	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(body, &data)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func getUptimeTracker(utURL string) (map[string]bool, error) {
	response := make(map[string]bool)
	res, err := http.Get(utURL + "/uptimes") //nolint
	if err != nil {
		return response, err
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return response, err
	}
	var data []uptimes
	err = json.Unmarshal(body, &data)
	if err != nil {
		return response, err
	}

	for _, visor := range data {
		response[visor.Key] = visor.Online
	}

	return response, nil
}

type uptimes struct {
	Key    string `json:"key"`
	Online bool   `json:"online"`
}

type visorTransports struct {
	Sudph []string `json:"sudph"`
	Stcpr []string `json:"stcpr"`
}

func getAREntries(arURL string) (data visorTransports, err error) {
	res, err := http.Get(arURL + "/transports") //nolint
	if err != nil {
		return visorTransports{}, err
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return visorTransports{}, err
	}

	err = json.Unmarshal(body, &data)
	if err != nil {
		return visorTransports{}, err
	}

	return data, err
}

func whitelistedPKs() map[string]bool {
	whitelistedPKs := make(map[string]bool)
	for _, pk := range strings.Split(utilenv.NetworkMonitorPKs, ",") {
		whitelistedPKs[pk] = true
	}
	for _, pk := range strings.Split(utilenv.TestNetworkMonitorPKs, ",") {
		whitelistedPKs[pk] = true
	}
	for _, pk := range strings.Split(utilenv.RouteSetupPKs, ",") {
		whitelistedPKs[pk] = true
	}
	for _, pk := range strings.Split(utilenv.TestRouteSetupPKs, ",") {
		whitelistedPKs[pk] = true
	}
	for _, pk := range strings.Split(utilenv.TPSetupPKs, ",") {
		whitelistedPKs[pk] = true
	}
	for _, pk := range strings.Split(utilenv.TestTPSetupPKs, ",") {
		whitelistedPKs[pk] = true
	}
	for _, pk := range strings.Split(utilenv.SurveyWhitelistPKs, ",") {
		whitelistedPKs[pk] = true
	}
	for _, pk := range strings.Split(utilenv.RewardSystemPKs, ",") {
		whitelistedPKs[pk] = true
	}
	return whitelistedPKs
}
