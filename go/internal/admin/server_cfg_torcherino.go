package admin

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"hazuki-go/internal/model"
	"hazuki-go/internal/storage"
)

func (s *server) configTorcherino(w http.ResponseWriter, r *http.Request) {
	st := getState(r.Context())
	title := s.t(r, "page.torcherino.title")
	cfg, err := s.config.GetDecryptedConfig()
	if err != nil {
		s.render(w, r, torcherinoData{
			layoutData: layoutData{
				Title:        title,
				BodyTemplate: "torcherino",
				User:         st.User,
				HasUsers:     st.HasUsers,
				Error:        err.Error(),
			},
		})
		return
	}

	switch r.Method {
	case http.MethodGet:
		notice := ""
		if r.URL.Query().Get("ok") != "" {
			notice = s.t(r, "common.saved")
		}
		s.renderTorcherinoForm(w, r, st, cfg, notice, "", strconv.Itoa(cfg.Ports.Torcherino), "", "", "", "", cfg.Torcherino.RedisCache.Enabled, "", "", "")
		return
	case http.MethodPost:
		// continue
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		s.renderTorcherinoForm(w, r, st, cfg, "", s.t(r, "error.badRequest"), strconv.Itoa(cfg.Ports.Torcherino), "", "", "", "", cfg.Torcherino.RedisCache.Enabled, "", "", "")
		return
	}

	serviceEnabled := parseBool(r.FormValue("serviceEnabled"), !cfg.Torcherino.Disabled)
	forwardClientIP := parseBool(r.FormValue("forwardClientIp"), cfg.Torcherino.ForwardClientIP)
	trustCfConnectingIP := parseBool(r.FormValue("trustCfConnectingIp"), cfg.Torcherino.TrustCfConnectingIP)

	defaultTarget := strings.TrimSpace(r.FormValue("defaultTarget"))
	hostMappingRaw := r.FormValue("hostMappingJson")
	hostMapping, err := parseHostMappingJSON(hostMappingRaw)
	if err != nil {
		draft := cfg
		draft.Torcherino.Disabled = !serviceEnabled
		draft.Torcherino.ForwardClientIP = forwardClientIP
		draft.Torcherino.TrustCfConnectingIP = trustCfConnectingIP
		draft.Torcherino.DefaultTarget = defaultTarget
		draft.Torcherino.HostMapping = hostMapping
		s.renderTorcherinoForm(w, r, st, draft, "", "HOST_MAPPING: "+err.Error(), r.FormValue("torcherinoPort"), defaultTarget, hostMappingRaw, r.FormValue("workerSecretHeaders"), r.FormValue("workerSecretHeaderMapJson"), parseBool(r.FormValue("redisCacheEnabled"), cfg.Torcherino.RedisCache.Enabled), r.FormValue("redisCacheMaxBodyBytes"), r.FormValue("redisCacheDefaultTTLSeconds"), r.FormValue("redisCacheMaxTTLSeconds"))
		return
	}

	workerSecretKey := r.FormValue("workerSecretKey")
	clearWorkerSecretKey := parseBool(r.FormValue("clearWorkerSecretKey"), false)

	workerSecretHeaders, err := parseHeaderNamesCSVStrict(r.FormValue("workerSecretHeaders"))
	if err != nil {
		draft := cfg
		draft.Torcherino.Disabled = !serviceEnabled
		draft.Torcherino.ForwardClientIP = forwardClientIP
		draft.Torcherino.TrustCfConnectingIP = trustCfConnectingIP
		draft.Torcherino.DefaultTarget = defaultTarget
		draft.Torcherino.HostMapping = hostMapping
		s.renderTorcherinoForm(w, r, st, draft, "", s.errText(r, err), r.FormValue("torcherinoPort"), defaultTarget, hostMappingRaw, r.FormValue("workerSecretHeaders"), r.FormValue("workerSecretHeaderMapJson"), parseBool(r.FormValue("redisCacheEnabled"), cfg.Torcherino.RedisCache.Enabled), r.FormValue("redisCacheMaxBodyBytes"), r.FormValue("redisCacheDefaultTTLSeconds"), r.FormValue("redisCacheMaxTTLSeconds"))
		return
	}

	clearWorkerSecretHeaderMap := parseBool(r.FormValue("clearWorkerSecretHeaderMap"), false)
	secretHeaderMapRaw := r.FormValue("workerSecretHeaderMapJson")
	mergedHeaderMap, err := mergeSecretHeaderMap(secretHeaderMapRaw, cfg.Torcherino.WorkerSecretHeaderMap, clearWorkerSecretHeaderMap)
	if err != nil {
		draft := cfg
		draft.Torcherino.Disabled = !serviceEnabled
		draft.Torcherino.ForwardClientIP = forwardClientIP
		draft.Torcherino.TrustCfConnectingIP = trustCfConnectingIP
		draft.Torcherino.DefaultTarget = defaultTarget
		draft.Torcherino.HostMapping = hostMapping
		s.renderTorcherinoForm(w, r, st, draft, "", s.errText(r, err), r.FormValue("torcherinoPort"), defaultTarget, hostMappingRaw, r.FormValue("workerSecretHeaders"), secretHeaderMapRaw, parseBool(r.FormValue("redisCacheEnabled"), cfg.Torcherino.RedisCache.Enabled), r.FormValue("redisCacheMaxBodyBytes"), r.FormValue("redisCacheDefaultTTLSeconds"), r.FormValue("redisCacheMaxTTLSeconds"))
		return
	}

	portRaw := strings.TrimSpace(r.FormValue("torcherinoPort"))
	redisCacheEnabled := parseBool(r.FormValue("redisCacheEnabled"), cfg.Torcherino.RedisCache.Enabled)
	maxBodyBytesRaw := strings.TrimSpace(r.FormValue("redisCacheMaxBodyBytes"))
	defaultTTLRaw := strings.TrimSpace(r.FormValue("redisCacheDefaultTTLSeconds"))
	maxTTLRaw := strings.TrimSpace(r.FormValue("redisCacheMaxTTLSeconds"))

	const maxCacheBodyBytes = 10 * 1024 * 1024
	const maxTTLSeconds = 315360000 // 10 years

	maxBodyBytes := 0
	if maxBodyBytesRaw != "" {
		n, err := strconv.Atoi(maxBodyBytesRaw)
		if err != nil || n < 0 || n > maxCacheBodyBytes {
			draft := cfg
			draft.Torcherino.Disabled = !serviceEnabled
			draft.Torcherino.ForwardClientIP = forwardClientIP
			draft.Torcherino.TrustCfConnectingIP = trustCfConnectingIP
			draft.Torcherino.DefaultTarget = defaultTarget
			draft.Torcherino.HostMapping = hostMapping
			s.renderTorcherinoForm(w, r, st, draft, "", s.t(r, "error.torcherino.cacheMaxBytesRange", maxCacheBodyBytes), portRaw, defaultTarget, hostMappingRaw, r.FormValue("workerSecretHeaders"), secretHeaderMapRaw, redisCacheEnabled, maxBodyBytesRaw, defaultTTLRaw, maxTTLRaw)
			return
		}
		maxBodyBytes = n
	}

	defaultTTLSeconds := 0
	if defaultTTLRaw != "" {
		n, err := strconv.Atoi(defaultTTLRaw)
		if err != nil || n < 0 || n > maxTTLSeconds {
			draft := cfg
			draft.Torcherino.Disabled = !serviceEnabled
			draft.Torcherino.ForwardClientIP = forwardClientIP
			draft.Torcherino.TrustCfConnectingIP = trustCfConnectingIP
			draft.Torcherino.DefaultTarget = defaultTarget
			draft.Torcherino.HostMapping = hostMapping
			s.renderTorcherinoForm(w, r, st, draft, "", s.t(r, "error.torcherino.cacheTTLRange", maxTTLSeconds), portRaw, defaultTarget, hostMappingRaw, r.FormValue("workerSecretHeaders"), secretHeaderMapRaw, redisCacheEnabled, maxBodyBytesRaw, defaultTTLRaw, maxTTLRaw)
			return
		}
		defaultTTLSeconds = n
	}

	maxTTLSecondsValue := 0
	if maxTTLRaw != "" {
		n, err := strconv.Atoi(maxTTLRaw)
		if err != nil || n < 0 || n > maxTTLSeconds {
			draft := cfg
			draft.Torcherino.Disabled = !serviceEnabled
			draft.Torcherino.ForwardClientIP = forwardClientIP
			draft.Torcherino.TrustCfConnectingIP = trustCfConnectingIP
			draft.Torcherino.DefaultTarget = defaultTarget
			draft.Torcherino.HostMapping = hostMapping
			s.renderTorcherinoForm(w, r, st, draft, "", s.t(r, "error.torcherino.cacheTTLRange", maxTTLSeconds), portRaw, defaultTarget, hostMappingRaw, r.FormValue("workerSecretHeaders"), secretHeaderMapRaw, redisCacheEnabled, maxBodyBytesRaw, defaultTTLRaw, maxTTLRaw)
			return
		}
		maxTTLSecondsValue = n
	}

	if maxTTLSecondsValue > 0 && defaultTTLSeconds > 0 && maxTTLSecondsValue < defaultTTLSeconds {
		draft := cfg
		draft.Torcherino.Disabled = !serviceEnabled
		draft.Torcherino.ForwardClientIP = forwardClientIP
		draft.Torcherino.TrustCfConnectingIP = trustCfConnectingIP
		draft.Torcherino.DefaultTarget = defaultTarget
		draft.Torcherino.HostMapping = hostMapping
		s.renderTorcherinoForm(w, r, st, draft, "", s.t(r, "error.torcherino.cacheMaxTTLTooSmall"), portRaw, defaultTarget, hostMappingRaw, r.FormValue("workerSecretHeaders"), secretHeaderMapRaw, redisCacheEnabled, maxBodyBytesRaw, defaultTTLRaw, maxTTLRaw)
		return
	}

	port, err := parsePort(portRaw, cfg.Ports.Torcherino)
	if err != nil {
		draft := cfg
		draft.Torcherino.Disabled = !serviceEnabled
		draft.Torcherino.DefaultTarget = defaultTarget
		draft.Torcherino.HostMapping = hostMapping
		s.renderTorcherinoForm(w, r, st, draft, "", s.errText(r, err), portRaw, defaultTarget, hostMappingRaw, r.FormValue("workerSecretHeaders"), secretHeaderMapRaw, redisCacheEnabled, maxBodyBytesRaw, defaultTTLRaw, maxTTLRaw)
		return
	}

	userID := st.User.ID
	clearSecrets := []string{}
	if clearWorkerSecretKey {
		clearSecrets = append(clearSecrets, "torcherino.workerSecretKey")
	}
	if clearWorkerSecretHeaderMap {
		clearSecrets = append(clearSecrets, "torcherino.workerSecretHeaderMap")
	}

	err = s.config.Update(storage.UpdateRequest{
		UserID:               &userID,
		Note:                 "edit:torcherino",
		PreserveEmptySecrets: true,
		ClearSecrets:         clearSecrets,
		Updater: func(cur model.AppConfig) (model.AppConfig, error) {
			next := cur
			next.Ports.Torcherino = port
			next.Torcherino.Disabled = !serviceEnabled
			next.Torcherino.DefaultTarget = defaultTarget
			next.Torcherino.HostMapping = hostMapping
			next.Torcherino.WorkerSecretHeaders = workerSecretHeaders
			next.Torcherino.ForwardClientIP = forwardClientIP
			next.Torcherino.TrustCfConnectingIP = trustCfConnectingIP
			next.Torcherino.RedisCache.Enabled = redisCacheEnabled
			next.Torcherino.RedisCache.MaxBodyBytes = maxBodyBytes
			next.Torcherino.RedisCache.DefaultTTLSeconds = defaultTTLSeconds
			next.Torcherino.RedisCache.MaxTTLSeconds = maxTTLSecondsValue
			if clearWorkerSecretKey {
				next.Torcherino.WorkerSecretKey = ""
			} else {
				next.Torcherino.WorkerSecretKey = workerSecretKey
			}
			next.Torcherino.WorkerSecretHeaderMap = mergedHeaderMap
			return next, nil
		},
	})
	if err != nil {
		draft := cfg
		draft.Ports.Torcherino = port
		draft.Torcherino.Disabled = !serviceEnabled
		draft.Torcherino.ForwardClientIP = forwardClientIP
		draft.Torcherino.TrustCfConnectingIP = trustCfConnectingIP
		draft.Torcherino.DefaultTarget = defaultTarget
		draft.Torcherino.HostMapping = hostMapping
		draft.Torcherino.WorkerSecretHeaders = workerSecretHeaders
		draft.Torcherino.WorkerSecretHeaderMap = mergedHeaderMap
		draft.Torcherino.RedisCache.Enabled = redisCacheEnabled
		draft.Torcherino.RedisCache.MaxBodyBytes = maxBodyBytes
		draft.Torcherino.RedisCache.DefaultTTLSeconds = defaultTTLSeconds
		draft.Torcherino.RedisCache.MaxTTLSeconds = maxTTLSecondsValue
		s.renderTorcherinoForm(w, r, st, draft, "", s.errText(r, err), portRaw, defaultTarget, hostMappingRaw, r.FormValue("workerSecretHeaders"), secretHeaderMapRaw, redisCacheEnabled, maxBodyBytesRaw, defaultTTLRaw, maxTTLRaw)
		return
	}

	http.Redirect(w, r, "/config/torcherino?ok=1", http.StatusFound)
}

func (s *server) renderTorcherinoForm(w http.ResponseWriter, r *http.Request, st *reqState, cfg model.AppConfig, notice, errMsg, torcherinoPortValue, defaultTargetValue, hostMappingJSONValue, workerSecretHeadersValue, workerSecretHeaderMapJSONValue string, redisCacheEnabled bool, redisCacheMaxBodyBytesValue, redisCacheDefaultTTLSecondsValue, redisCacheMaxTTLSecondsValue string) {
	if strings.TrimSpace(torcherinoPortValue) == "" {
		torcherinoPortValue = strconv.Itoa(cfg.Ports.Torcherino)
	}
	if strings.TrimSpace(defaultTargetValue) == "" {
		defaultTargetValue = cfg.Torcherino.DefaultTarget
	}
	if strings.TrimSpace(hostMappingJSONValue) == "" {
		pretty, _ := json.MarshalIndent(cfg.Torcherino.HostMapping, "", "  ")
		hostMappingJSONValue = string(pretty)
	}

	redacted, _ := s.config.GetRedactedConfig()
	workerSecretKeyValue := ""
	secretIsSet := strings.TrimSpace(cfg.Torcherino.WorkerSecretKey) != ""
	if !secretIsSet && strings.TrimSpace(redacted.Torcherino.WorkerSecretKey) != "" {
		secretIsSet = true
	}

	if strings.TrimSpace(workerSecretHeadersValue) == "" {
		workerSecretHeadersValue = strings.Join(cfg.Torcherino.WorkerSecretHeaders, ", ")
	}
	if strings.TrimSpace(workerSecretHeaderMapJSONValue) == "" {
		pretty, _ := json.MarshalIndent(redacted.Torcherino.WorkerSecretHeaderMap, "", "  ")
		workerSecretHeaderMapJSONValue = string(pretty)
	}

	if strings.TrimSpace(redisCacheMaxBodyBytesValue) == "" {
		if cfg.Torcherino.RedisCache.MaxBodyBytes > 0 {
			redisCacheMaxBodyBytesValue = strconv.Itoa(cfg.Torcherino.RedisCache.MaxBodyBytes)
		}
	}
	if strings.TrimSpace(redisCacheDefaultTTLSecondsValue) == "" {
		if cfg.Torcherino.RedisCache.DefaultTTLSeconds > 0 {
			redisCacheDefaultTTLSecondsValue = strconv.Itoa(cfg.Torcherino.RedisCache.DefaultTTLSeconds)
		}
	}
	if strings.TrimSpace(redisCacheMaxTTLSecondsValue) == "" {
		if cfg.Torcherino.RedisCache.MaxTTLSeconds > 0 {
			redisCacheMaxTTLSecondsValue = strconv.Itoa(cfg.Torcherino.RedisCache.MaxTTLSeconds)
		}
	}

	baseURL := baseURLForPort(r, cfg.Ports.Torcherino)
	torcherinoSt := func() serviceStatus {
		if cfg.Torcherino.Disabled {
			return disabledServiceStatus(cfg.Ports.Torcherino)
		}
		return checkServiceStatus(r.Context(), cfg.Ports.Torcherino)
	}()

	s.render(w, r, torcherinoData{
		layoutData: layoutData{
			Title:        s.t(r, "page.torcherino.title"),
			BodyTemplate: "torcherino",
			User:         st.User,
			HasUsers:     st.HasUsers,
			Notice:       notice,
			Error:        errMsg,
		},
		Torcherino: cfg.Torcherino,

		TorcherinoPort:      cfg.Ports.Torcherino,
		TorcherinoPortValue: torcherinoPortValue,

		DefaultTargetValue: defaultTargetValue,
		HostMappingJSON:    hostMappingJSONValue,

		SecretIsSet:                    secretIsSet,
		WorkerSecretKeyValue:           workerSecretKeyValue,
		WorkerSecretHeadersCsvValue:    workerSecretHeadersValue,
		WorkerSecretHeaderMapJSONValue: workerSecretHeaderMapJSONValue,

		RedisCacheEnabled:                redisCacheEnabled,
		RedisCacheMaxBodyBytesValue:      redisCacheMaxBodyBytesValue,
		RedisCacheDefaultTTLSecondsValue: redisCacheDefaultTTLSecondsValue,
		RedisCacheMaxTTLSecondsValue:     redisCacheMaxTTLSecondsValue,

		TorcherinoBaseURL:   baseURL,
		TorcherinoHealthURL: "/_hazuki/health/torcherino",
		TorcherinoStatus:    torcherinoSt,
	})
}
