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
			Tpd: make(map[string]bool),
		},
		deadEntries: nm.DeadEntries{
			Tpd: []string{},
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
		api.logger.WithError(err).Warnf("Error Getting all summaries")
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
			api.deregister(ctx)
			api.store.SetNetworkStatus(api.status)
		}
	}
}

// deregister use as routine to deregister old/dead entries in the network
func (api *API) deregister(ctx context.Context) {
	api.logger.Info("Deregistration routine start.")
	defer api.dMu.Unlock()
	api.dMu.Lock()

	api.status.LastUpdate = time.Now().UTC()
	fmt.Println(api.status.LastUpdate)
	// get uptime tracker in each itterate
	api.getUptimeTracker(ctx) //nolint
	api.status.OnlineVisors = len(api.utData)

	api.tpdDeregistration(ctx) //nolint
	time.Sleep(5 * time.Second)
	// api.dmsgdDeregistration(ctx)
	// time.Sleep(75 * time.Second)
	// api.arDeregistration(ctx)
	// time.Sleep(75 * time.Second)
	// api.sdDeregistration(ctx)
	// time.Sleep(75 * time.Second)

	api.logger.Info("Deregistration routine completed.")
}

func (api *API) tpdDeregistration(ctx context.Context) error {
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
		return nil
	}
}

// arDeregistration is a routine to deregister dead entries in address resolver transports
// func (api *API) arDeregistration(ctx context.Context, uptimes map[string]bool) {
// 	api.logger.Info("AR Deregistration started.")
// 	allSudphCount, allStcprCount := 0, 0
// 	arKeys := make(map[cipher.PubKey]visorDetails)
// 	for key, details := range api.visorDetails {
// 		arKeys[key] = details

// 		if details.IsStcpr {
// 			allStcprCount++
// 		}
// 		if details.IsOnline {
// 			allSudphCount++
// 		}
// 	}
// 	if len(arKeys) == 0 {
// 		api.logger.Warn("No visor keys found")
// 		return
// 	}

// 	checkRes := arCheckerResult{
// 		deadStcpr: &[]string{},
// 		deadSudph: &[]string{},
// 	}

// 	checkConf := arChekerConfig{
// 		ctx:     ctx,
// 		wg:      new(sync.WaitGroup),
// 		uptimes: uptimes,
// 	}

// 	tmpBatchSize := 0
// 	for key, details := range arKeys {
// 		if _, ok := api.whitelistedPKs[key.Hex()]; ok {
// 			continue
// 		}
// 		tmpBatchSize++
// 		checkConf.wg.Add(1)
// 		checkConf.key = key
// 		checkConf.details = details
// 		go api.arChecker(checkConf, &checkRes)
// 		if tmpBatchSize == api.batchSize {
// 			time.Sleep(time.Minute)
// 			tmpBatchSize = 0
// 		}
// 	}
// 	checkConf.wg.Wait()

// 	stcprCounter := int64(allStcprCount - len(*checkRes.deadStcpr))
// 	sudphCounter := int64(allSudphCount - len(*checkRes.deadSudph))

// 	api.logger.WithField("sudph", sudphCounter).WithField("stcpr", stcprCounter).Info("Transports online.")
// 	api.metrics.SetTpCount(stcprCounter, sudphCounter)

// 	if len(*checkRes.deadStcpr) > 0 {
// 		api.arDeregister(*checkRes.deadStcpr, "stcpr")
// 	}
// 	api.logger.WithField("Number of dead Stcpr", len(*checkRes.deadStcpr)).WithField("PKs", checkRes.deadStcpr).Info("STCPR deregistration complete.")

// 	if len(*checkRes.deadSudph) > 0 {
// 		api.arDeregister(*checkRes.deadSudph, "sudph")
// 	}
// 	api.logger.WithField("Number of dead Sudph", len(*checkRes.deadSudph)).WithField("PKs", checkRes.deadSudph).Info("SUDPH deregistration complete.")

// 	api.logger.Info("AR Deregistration completed.")
// }

// func (api *API) arChecker(cfg arChekerConfig, res *arCheckerResult) {
// 	defer cfg.wg.Done()
// 	visorSum, err := api.store.GetVisorByPk(cfg.key.String())
// 	if err != nil {
// 		api.logger.WithError(err).Debugf("Failed to fetch visor summary of PK %s in AR deregister procces.", cfg.key.Hex())
// 		if err != store.ErrVisorSumNotFound {
// 			return
// 		}
// 	}

// 	stcprC := make(chan bool)
// 	sudphC := make(chan bool)
// 	if cfg.details.IsStcpr {
// 		go api.testTransport(cfg.key, network.STCPR, stcprC)
// 	}
// 	if cfg.details.IsOnline {
// 		go api.testTransport(cfg.key, network.SUDPH, sudphC)
// 	}

// 	if cfg.details.IsStcpr {
// 		visorSum.Stcpr = <-stcprC
// 	}
// 	if cfg.details.IsOnline {
// 		visorSum.Sudph = <-sudphC
// 	}
// 	visorSum.Timestamp = time.Now().Unix()
// 	api.mu.Lock()
// 	err = api.store.AddVisorSummary(cfg.ctx, cfg.key, visorSum)
// 	if err != nil {
// 		api.logger.WithError(err).Warnf("Failed to save Visor summary of %v", cfg.key)
// 	}

// 	if cfg.details.IsStcpr && !visorSum.Stcpr {
// 		*res.deadStcpr = append(*res.deadStcpr, cfg.key.Hex())
// 	}

// 	if cfg.details.IsOnline && !visorSum.Sudph {
// 		*res.deadSudph = append(*res.deadSudph, cfg.key.Hex())
// 	}

// 	api.mu.Unlock()
// }

// func (api *API) testTransport(key cipher.PubKey, transport network.Type, ch chan bool) {
// 	var isUp bool
// 	retrier := 3
// 	for retrier > 0 {
// 		tp, err := api.Visor.AddTransport(key, string(transport), time.Second*3)
// 		if err != nil {
// 			api.logger.WithField("Retry", 4-retrier).WithError(err).Warnf("Failed to establish %v transport to %v", transport, key)
// 			retrier--
// 			continue
// 		}

// 		api.logger.Infof("Established %v transport to %v", transport, key)
// 		isUp = true
// 		err = api.Visor.RemoveTransport(tp.ID)
// 		if err != nil {
// 			api.logger.Warnf("Error removing %v transport of %v: %v", transport, key, err)
// 		}
// 		retrier = 0
// 	}

// 	ch <- isUp
// }

func (api *API) tpdDeregister(keys []string) {
	err := api.deregisterRequest(keys, fmt.Sprintf("%s/deregister", api.tpdURL), "transport-discovery")
	if err != nil {
		api.logger.Warn(err)
		return
	}
	api.logger.Info("Deregister request send to Tpd")
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

// type visorTransports struct {
// 	Sudph []cipher.PubKey `json:"sudph"`
// 	Stcpr []cipher.PubKey `json:"stcpr"`
// }

// func getVisors(arURL string) (data visorTransports, err error) {
// 	res, err := http.Get(arURL + "/transports") //nolint

// 	if err != nil {
// 		return visorTransports{}, err
// 	}

// 	body, err := io.ReadAll(res.Body)

// 	if err != nil {
// 		return visorTransports{}, err
// 	}
// 	err = json.Unmarshal(body, &data)
// 	if err != nil {
// 		return visorTransports{}, err
// 	}
// 	return data, err
// }

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
		api.utData = response
		return nil
	}
}

type uptimes struct {
	Key    string `json:"key"`
	Online bool   `json:"online"`
}

// func (api *API) getVisorKeys() {
// 	api.visorDetails = make(map[cipher.PubKey]visorDetails)
// 	visorTs, err := getVisors(api.arURL)
// 	if err != nil {
// 		api.logger.Warnf("Error while fetching visors: %v", err)
// 		return
// 	}
// 	if len(visorTs.Stcpr) == 0 && len(visorTs.Sudph) == 0 {
// 		api.logger.Warn("No visors found... Will try again")
// 	}
// 	for _, visorPk := range visorTs.Stcpr {
// 		if visorPk != api.nmPk {
// 			detail := api.visorDetails[visorPk]
// 			detail.IsStcpr = true
// 			api.visorDetails[visorPk] = detail
// 		}
// 	}
// 	for _, visorPk := range visorTs.Sudph {
// 		if visorPk != api.nmPk {
// 			detail := api.visorDetails[visorPk]
// 			detail.IsOnline = true
// 			api.visorDetails[visorPk] = detail
// 		}
// 	}

// 	api.logger.WithField("visors", len(api.visorDetails)).Info("Visor keys updated.")
// 	api.metrics.SetTotalVisorCount(int64(len(api.visorDetails)))
// }

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
