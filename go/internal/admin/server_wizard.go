package admin

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"hazuki-go/internal/model"
	"hazuki-go/internal/storage"
)

func (s *server) wizard(w http.ResponseWriter, r *http.Request) {
	st := getState(r.Context())
	title := s.t(r, "page.wizard.title")
	current, err := s.config.GetDecryptedConfig()
	if err != nil {
		s.render(w, r, wizardData{
			layoutData: layoutData{
				Title:        title,
				BodyTemplate: "wizard",
				User:         st.User,
				HasUsers:     st.HasUsers,
				Error:        err.Error(),
			},
		})
		return
	}
	redacted, _ := s.config.GetRedactedConfig()

	switch r.Method {
	case http.MethodGet:
		notice := ""
		if r.URL.Query().Get("ok") != "" {
			notice = s.t(r, "common.saved")
		}

		hostMappingJSON, _ := json.MarshalIndent(current.Torcherino.HostMapping, "", "  ")
		headerMapJSON, _ := json.MarshalIndent(redacted.Torcherino.WorkerSecretHeaderMap, "", "  ")

		s.render(w, r, wizardData{
			layoutData: layoutData{
				Title:        title,
				BodyTemplate: "wizard",
				User:         st.User,
				HasUsers:     st.HasUsers,
				Notice:       notice,
			},
			TokenIsSet:  strings.TrimSpace(current.Git.GithubToken) != "",
			SecretIsSet: strings.TrimSpace(current.Torcherino.WorkerSecretKey) != "",

			TorcherinoDefaultTarget:         current.Torcherino.DefaultTarget,
			TorcherinoHostMappingJSON:       string(hostMappingJSON),
			TorcherinoWorkerSecretKey:       "",
			TorcherinoWorkerSecretHeaders:   strings.Join(current.Torcherino.WorkerSecretHeaders, ", "),
			TorcherinoWorkerSecretHeaderMap: string(headerMapJSON),

			CdnjsDefaultGhUser:  current.Cdnjs.DefaultGhUser,
			CdnjsAllowedGhUsers: strings.Join(current.Cdnjs.AllowedGhUsers, ", "),
			CdnjsGhUserPolicy:   strings.TrimSpace(current.Cdnjs.GhUserPolicy),
			CdnjsBlockedGhUsers: strings.Join(current.Cdnjs.BlockedGhUsers, ", "),
			CdnjsAssetURL:       current.Cdnjs.AssetURL,
			CdnjsRedisHost:      current.Cdnjs.Redis.Host,
			CdnjsRedisPort:      strconv.Itoa(current.Cdnjs.Redis.Port),

			GitUpstreamPath: current.Git.UpstreamPath,
		})
		return
	case http.MethodPost:
		// continue
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		s.render(w, r, wizardData{
			layoutData: layoutData{
				Title:        title,
				BodyTemplate: "wizard",
				User:         st.User,
				HasUsers:     st.HasUsers,
				Error:        s.t(r, "error.badRequest"),
			},
		})
		return
	}

	form := wizardData{
		layoutData: layoutData{
			Title:        title,
			BodyTemplate: "wizard",
			User:         st.User,
			HasUsers:     st.HasUsers,
		},
		TokenIsSet:  strings.TrimSpace(current.Git.GithubToken) != "",
		SecretIsSet: strings.TrimSpace(current.Torcherino.WorkerSecretKey) != "",

		TorcherinoDefaultTarget:         strings.TrimSpace(r.FormValue("torcherinoDefaultTarget")),
		TorcherinoHostMappingJSON:       r.FormValue("torcherinoHostMappingJson"),
		TorcherinoWorkerSecretKey:       r.FormValue("torcherinoWorkerSecretKey"),
		TorcherinoWorkerSecretHeaders:   strings.TrimSpace(r.FormValue("torcherinoWorkerSecretHeaders")),
		TorcherinoWorkerSecretHeaderMap: r.FormValue("torcherinoWorkerSecretHeaderMapJson"),

		CdnjsDefaultGhUser:  strings.TrimSpace(r.FormValue("cdnjsDefaultGhUser")),
		CdnjsAllowedGhUsers: strings.TrimSpace(r.FormValue("cdnjsAllowedGhUsers")),
		CdnjsGhUserPolicy:   strings.TrimSpace(r.FormValue("cdnjsGhUserPolicy")),
		CdnjsBlockedGhUsers: strings.TrimSpace(r.FormValue("cdnjsBlockedGhUsers")),
		CdnjsAssetURL:       strings.TrimSpace(r.FormValue("cdnjsAssetUrl")),
		CdnjsRedisHost:      strings.TrimSpace(r.FormValue("cdnjsRedisHost")),
		CdnjsRedisPort:      strings.TrimSpace(r.FormValue("cdnjsRedisPort")),

		GitUpstreamPath: strings.TrimSpace(r.FormValue("gitUpstreamPath")),
		GitGithubToken:  r.FormValue("gitGithubToken"),
	}

	clearGitToken := parseBool(r.FormValue("gitClearGithubToken"), false)
	clearWorkerSecretKey := parseBool(r.FormValue("torcherinoClearWorkerSecretKey"), false)
	clearWorkerSecretHeaderMap := parseBool(r.FormValue("torcherinoClearWorkerSecretHeaderMap"), false)

	hostMapping, err := parseHostMappingJSON(form.TorcherinoHostMappingJSON)
	if err != nil {
		form.Error = "HOST_MAPPING: " + err.Error()
		s.render(w, r, form)
		return
	}

	workerSecretHeaders, err := parseHeaderNamesCSVStrict(form.TorcherinoWorkerSecretHeaders)
	if err != nil {
		form.Error = s.errText(r, err)
		s.render(w, r, form)
		return
	}

	mergedHeaderMap, err := mergeSecretHeaderMap(form.TorcherinoWorkerSecretHeaderMap, current.Torcherino.WorkerSecretHeaderMap, clearWorkerSecretHeaderMap)
	if err != nil {
		form.Error = s.errText(r, err)
		s.render(w, r, form)
		return
	}

	defaultTarget := form.TorcherinoDefaultTarget
	hasDefault := strings.TrimSpace(defaultTarget) != ""
	hasMapping := len(hostMapping) > 0
	if !hasDefault && !hasMapping {
		form.Error = s.t(r, "error.torcherino.needDefaultOrMap")
		s.render(w, r, form)
		return
	}

	cdnjsAllowed := parseCSV(form.CdnjsAllowedGhUsers)
	cdnjsBlocked := parseCSV(form.CdnjsBlockedGhUsers)
	ghUserPolicy := strings.ToLower(strings.TrimSpace(form.CdnjsGhUserPolicy))
	if ghUserPolicy == "" {
		ghUserPolicy = "allowlist"
	}
	if ghUserPolicy != "allowlist" && ghUserPolicy != "denylist" {
		form.Error = s.t(r, "error.cdnjs.ghUserPolicyInvalid")
		s.render(w, r, form)
		return
	}
	if ghUserPolicy == "allowlist" && strings.TrimSpace(form.CdnjsDefaultGhUser) == "" && len(cdnjsAllowed) == 0 {
		form.Error = s.t(r, "error.cdnjs.allowlistNeedDefaultOrAllowed")
		s.render(w, r, form)
		return
	}

	assetURL := strings.TrimSpace(form.CdnjsAssetURL)
	if assetURL == "" {
		assetURL = current.Cdnjs.AssetURL
	}
	assetURL = strings.TrimRight(assetURL, "/")
	if u, err := url.Parse(assetURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || strings.TrimSpace(u.Host) == "" {
		form.Error = s.t(r, "error.cdnjs.assetUrlInvalid")
		s.render(w, r, form)
		return
	}

	redisHost := strings.TrimSpace(form.CdnjsRedisHost)
	if redisHost == "" {
		redisHost = current.Cdnjs.Redis.Host
	}

	redisPort, err := parsePort(form.CdnjsRedisPort, current.Cdnjs.Redis.Port)
	if err != nil {
		form.Error = s.errText(r, err)
		s.render(w, r, form)
		return
	}

	upstreamPath := normalizePath(form.GitUpstreamPath)
	parts := strings.Split(strings.Trim(upstreamPath, "/"), "/")
	if len(parts) < 3 {
		form.Error = s.t(r, "error.git.upstreamPathTooShort")
		s.render(w, r, form)
		return
	}

	userID := st.User.ID
	clearSecrets := []string{}
	if clearGitToken {
		clearSecrets = append(clearSecrets, "git.githubToken")
	}
	if clearWorkerSecretKey {
		clearSecrets = append(clearSecrets, "torcherino.workerSecretKey")
	}
	if clearWorkerSecretHeaderMap {
		clearSecrets = append(clearSecrets, "torcherino.workerSecretHeaderMap")
	}

	err = s.config.Update(storage.UpdateRequest{
		UserID:               &userID,
		Note:                 "wizard",
		PreserveEmptySecrets: true,
		ClearSecrets:         clearSecrets,
		Updater: func(cur model.AppConfig) (model.AppConfig, error) {
			next := cur

			next.Torcherino.DefaultTarget = defaultTarget
			next.Torcherino.HostMapping = hostMapping
			next.Torcherino.WorkerSecretHeaders = workerSecretHeaders
			if clearWorkerSecretKey {
				next.Torcherino.WorkerSecretKey = ""
			} else {
				next.Torcherino.WorkerSecretKey = form.TorcherinoWorkerSecretKey
			}
			next.Torcherino.WorkerSecretHeaderMap = mergedHeaderMap

			next.Cdnjs.DefaultGhUser = form.CdnjsDefaultGhUser
			next.Cdnjs.GhUserPolicy = ghUserPolicy
			next.Cdnjs.AllowedGhUsers = cdnjsAllowed
			next.Cdnjs.BlockedGhUsers = cdnjsBlocked
			next.Cdnjs.AssetURL = assetURL
			next.Cdnjs.Redis.Host = redisHost
			next.Cdnjs.Redis.Port = redisPort

			next.Git.UpstreamPath = upstreamPath
			if clearGitToken {
				next.Git.GithubToken = ""
			} else {
				next.Git.GithubToken = form.GitGithubToken
			}

			return next, nil
		},
	})
	if err != nil {
		form.Error = s.errText(r, err)
		s.render(w, r, form)
		return
	}

	http.Redirect(w, r, "/wizard?ok=1", http.StatusFound)
}
