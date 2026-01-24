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
		s.renderTorcherinoForm(w, r, st, cfg, notice, "", strconv.Itoa(cfg.Ports.Torcherino), "", "", "", "")
		return
	case http.MethodPost:
		// continue
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		s.renderTorcherinoForm(w, r, st, cfg, "", s.t(r, "error.badRequest"), strconv.Itoa(cfg.Ports.Torcherino), "", "", "", "")
		return
	}

	serviceEnabled := parseBool(r.FormValue("serviceEnabled"), !cfg.Torcherino.Disabled)

	defaultTarget := strings.TrimSpace(r.FormValue("defaultTarget"))
	hostMappingRaw := r.FormValue("hostMappingJson")
	hostMapping, err := parseHostMappingJSON(hostMappingRaw)
	if err != nil {
		draft := cfg
		draft.Torcherino.Disabled = !serviceEnabled
		draft.Torcherino.DefaultTarget = defaultTarget
		draft.Torcherino.HostMapping = hostMapping
		s.renderTorcherinoForm(w, r, st, draft, "", "HOST_MAPPING: "+err.Error(), r.FormValue("torcherinoPort"), defaultTarget, hostMappingRaw, r.FormValue("workerSecretHeaders"), r.FormValue("workerSecretHeaderMapJson"))
		return
	}

	workerSecretKey := r.FormValue("workerSecretKey")
	clearWorkerSecretKey := parseBool(r.FormValue("clearWorkerSecretKey"), false)

	workerSecretHeaders, err := parseHeaderNamesCSVStrict(r.FormValue("workerSecretHeaders"))
	if err != nil {
		draft := cfg
		draft.Torcherino.Disabled = !serviceEnabled
		draft.Torcherino.DefaultTarget = defaultTarget
		draft.Torcherino.HostMapping = hostMapping
		s.renderTorcherinoForm(w, r, st, draft, "", s.errText(r, err), r.FormValue("torcherinoPort"), defaultTarget, hostMappingRaw, r.FormValue("workerSecretHeaders"), r.FormValue("workerSecretHeaderMapJson"))
		return
	}

	clearWorkerSecretHeaderMap := parseBool(r.FormValue("clearWorkerSecretHeaderMap"), false)
	secretHeaderMapRaw := r.FormValue("workerSecretHeaderMapJson")
	mergedHeaderMap, err := mergeSecretHeaderMap(secretHeaderMapRaw, cfg.Torcherino.WorkerSecretHeaderMap, clearWorkerSecretHeaderMap)
	if err != nil {
		draft := cfg
		draft.Torcherino.Disabled = !serviceEnabled
		draft.Torcherino.DefaultTarget = defaultTarget
		draft.Torcherino.HostMapping = hostMapping
		s.renderTorcherinoForm(w, r, st, draft, "", s.errText(r, err), r.FormValue("torcherinoPort"), defaultTarget, hostMappingRaw, r.FormValue("workerSecretHeaders"), secretHeaderMapRaw)
		return
	}

	portRaw := strings.TrimSpace(r.FormValue("torcherinoPort"))
	port, err := parsePort(portRaw, cfg.Ports.Torcherino)
	if err != nil {
		draft := cfg
		draft.Torcherino.Disabled = !serviceEnabled
		draft.Torcherino.DefaultTarget = defaultTarget
		draft.Torcherino.HostMapping = hostMapping
		s.renderTorcherinoForm(w, r, st, draft, "", s.errText(r, err), portRaw, defaultTarget, hostMappingRaw, r.FormValue("workerSecretHeaders"), secretHeaderMapRaw)
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
		draft.Torcherino.DefaultTarget = defaultTarget
		draft.Torcherino.HostMapping = hostMapping
		draft.Torcherino.WorkerSecretHeaders = workerSecretHeaders
		draft.Torcherino.WorkerSecretHeaderMap = mergedHeaderMap
		s.renderTorcherinoForm(w, r, st, draft, "", s.errText(r, err), portRaw, defaultTarget, hostMappingRaw, r.FormValue("workerSecretHeaders"), secretHeaderMapRaw)
		return
	}

	http.Redirect(w, r, "/config/torcherino?ok=1", http.StatusFound)
}

func (s *server) renderTorcherinoForm(w http.ResponseWriter, r *http.Request, st *reqState, cfg model.AppConfig, notice, errMsg, torcherinoPortValue, defaultTargetValue, hostMappingJSONValue, workerSecretHeadersValue, workerSecretHeaderMapJSONValue string) {
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

		TorcherinoBaseURL:   baseURL,
		TorcherinoHealthURL: "/_hazuki/health/torcherino",
		TorcherinoStatus:    torcherinoSt,
	})
}
