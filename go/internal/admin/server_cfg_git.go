package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"hazuki-go/internal/model"
	"hazuki-go/internal/storage"
)

func (s *server) configGit(w http.ResponseWriter, r *http.Request) {
	st := getState(r.Context())
	title := s.t(r, "page.git.title")

	cfg, err := s.config.GetDecryptedConfig()
	if err != nil {
		s.render(w, r, gitData{
			layoutData: layoutData{
				Title:        title,
				BodyTemplate: "git",
				User:         st.User,
				HasUsers:     st.HasUsers,
				Error:        err.Error(),
			},
		})
		return
	}

	instanceID := strings.TrimSpace(r.URL.Query().Get("instance"))

	switch r.Method {
	case http.MethodGet:
		notice := ""
		if r.URL.Query().Get("added") != "" {
			if instanceID != "" && !strings.EqualFold(instanceID, "default") {
				port := 0
				for _, it := range cfg.GitInstances {
					if strings.EqualFold(strings.TrimSpace(it.ID), instanceID) {
						port = it.Port
						break
					}
				}
				if port > 0 {
					notice = adminI18n.T(
						s.pickLang(r),
						"git.instanceCreated",
						instanceID,
						port,
						port,
						port,
					)
				} else {
					notice = adminI18n.T(s.pickLang(r), "git.instanceCreatedShort")
				}
			} else {
				notice = adminI18n.T(s.pickLang(r), "git.instanceCreatedShort")
			}
		} else if r.URL.Query().Get("ok") != "" {
			notice = adminI18n.T(s.pickLang(r), "common.saved")
		}
		s.renderGitForm(w, r, st, cfg, instanceID, notice, "", "", "")
		return
	case http.MethodPost:
		// continue
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		s.renderGitForm(w, r, st, cfg, instanceID, "", s.t(r, "error.badRequest"), "", "")
		return
	}

	action := strings.TrimSpace(r.FormValue("action"))
	if action == "addInstance" {
		newID := strings.TrimSpace(r.FormValue("newInstanceID"))
		newName := strings.TrimSpace(r.FormValue("newInstanceName"))
		newPortRaw := strings.TrimSpace(r.FormValue("newInstancePort"))
		if newID == "" {
			s.renderGitForm(w, r, st, cfg, "", "", s.t(r, "error.git.instanceIdRequired"), "", "")
			return
		}
		if strings.EqualFold(newID, "default") {
			s.renderGitForm(w, r, st, cfg, "", "", s.t(r, "error.git.instanceIdReserved"), "", "")
			return
		}
		if newPortRaw == "" {
			s.renderGitForm(w, r, st, cfg, "", "", s.t(r, "error.portRequired"), "", "")
			return
		}
		newPort, err := parsePort(newPortRaw, 0)
		if err != nil {
			s.renderGitForm(w, r, st, cfg, "", "", s.errText(r, err), "", "")
			return
		}

		enabled := parseBool(r.FormValue("newInstanceEnabled"), true)

		userID := st.User.ID
		err = s.config.Update(storage.UpdateRequest{
			UserID: &userID,
			Note:   "add:gitInstance",
			Updater: func(cur model.AppConfig) (model.AppConfig, error) {
				next := cur
				for _, it := range next.GitInstances {
					if strings.EqualFold(strings.TrimSpace(it.ID), newID) {
						return model.AppConfig{}, errI18n("error.git.instanceExists", newID)
					}
				}

				gi := model.GitInstanceConfig{
					ID:   newID,
					Name: newName,
					Port: newPort,
					Git:  next.Git, // copy from default
				}
				gi.Git.Disabled = !enabled
				next.GitInstances = append(next.GitInstances, gi)
				return next, nil
			},
		})
		if err != nil {
			s.renderGitForm(w, r, st, cfg, "", "", s.errText(r, err), "", "")
			return
		}
		http.Redirect(w, r, "/config/git?ok=1&added=1&instance="+url.QueryEscape(newID), http.StatusFound)
		return
	}
	if action == "deleteInstance" {
		delID := strings.TrimSpace(r.FormValue("instanceID"))
		if delID == "" {
			s.renderGitForm(w, r, st, cfg, "", "", s.t(r, "error.git.instanceIdRequired"), "", "")
			return
		}

		userID := st.User.ID
		err = s.config.Update(storage.UpdateRequest{
			UserID: &userID,
			Note:   "delete:gitInstance",
			Updater: func(cur model.AppConfig) (model.AppConfig, error) {
				next := cur
				out := make([]model.GitInstanceConfig, 0, len(next.GitInstances))
				found := false
				for _, it := range next.GitInstances {
					if strings.EqualFold(strings.TrimSpace(it.ID), delID) {
						found = true
						continue
					}
					out = append(out, it)
				}
				if !found {
					return model.AppConfig{}, errI18n("error.git.instanceNotFound", delID)
				}
				next.GitInstances = out
				return next, nil
			},
		})
		if err != nil {
			s.renderGitForm(w, r, st, cfg, "", "", s.errText(r, err), "", "")
			return
		}
		http.Redirect(w, r, "/config/git?ok=1", http.StatusFound)
		return
	}

	// Default or instance config update.
	instanceID = strings.TrimSpace(r.FormValue("instanceID"))
	isInstance := instanceID != ""
	serviceEnabledFallback := !cfg.Git.Disabled
	if isInstance {
		for _, it := range cfg.GitInstances {
			if strings.EqualFold(strings.TrimSpace(it.ID), instanceID) {
				serviceEnabledFallback = !it.Git.Disabled
				break
			}
		}
	}
	serviceEnabled := parseBool(r.FormValue("serviceEnabled"), serviceEnabledFallback)

	githubAuthScheme := strings.TrimSpace(r.FormValue("githubAuthScheme"))
	if githubAuthScheme == "" {
		githubAuthScheme = "token"
	}

	upstream := strings.TrimSpace(r.FormValue("upstream"))
	if upstream == "" {
		upstream = "raw.githubusercontent.com"
	}
	upstreamMobile := strings.TrimSpace(r.FormValue("upstreamMobile"))
	if upstreamMobile == "" {
		upstreamMobile = upstream
	}
	upstreamPath := normalizePath(r.FormValue("upstreamPath"))

	githubToken := r.FormValue("githubToken")
	clearGithubToken := parseBool(r.FormValue("clearGithubToken"), false)

	httpsEnabled := parseBool(r.FormValue("upstreamHttps"), false)
	disableCache := parseBool(r.FormValue("disableCache"), false)
	cacheControl := strings.TrimSpace(r.FormValue("cacheControl"))
	cacheControlMedia := strings.TrimSpace(r.FormValue("cacheControlMedia"))
	cacheControlText := strings.TrimSpace(r.FormValue("cacheControlText"))

	corsOrigin := strings.TrimSpace(r.FormValue("corsOrigin"))
	if corsOrigin == "" {
		corsOrigin = "*"
	}
	corsAllowCredentials := parseBool(r.FormValue("corsAllowCredentials"), false)
	corsExposeHeaders := strings.TrimSpace(r.FormValue("corsExposeHeaders"))

	blockedRegions := parseCSV(r.FormValue("blockedRegions"))
	blockedIPs := parseCSV(r.FormValue("blockedIpAddresses"))

	draft := cfg
	applyDraftGit := func(g *model.GitConfig) {
		g.Disabled = !serviceEnabled
		g.Upstream = upstream
		g.UpstreamMobile = upstreamMobile
		g.UpstreamPath = upstreamPath
		g.HTTPS = httpsEnabled
		g.GithubAuthScheme = githubAuthScheme
		g.DisableCache = disableCache
		g.CacheControl = cacheControl
		g.CacheControlMedia = cacheControlMedia
		g.CacheControlText = cacheControlText
		g.CorsOrigin = corsOrigin
		g.CorsAllowCredentials = corsAllowCredentials
		g.CorsExposeHeaders = corsExposeHeaders
		g.BlockedRegions = blockedRegions
		g.BlockedIpAddresses = blockedIPs
	}

	if isInstance {
		found := false
		for i := range draft.GitInstances {
			if strings.EqualFold(strings.TrimSpace(draft.GitInstances[i].ID), instanceID) {
				found = true
				applyDraftGit(&draft.GitInstances[i].Git)
				break
			}
		}
		if !found {
			s.renderGitForm(w, r, st, cfg, "", "", s.t(r, "error.git.instanceNotFound", instanceID), "", r.FormValue("replaceDictJson"))
			return
		}
	} else {
		applyDraftGit(&draft.Git)
	}
	if clearGithubToken {
		if isInstance {
			for i := range draft.GitInstances {
				if strings.EqualFold(strings.TrimSpace(draft.GitInstances[i].ID), instanceID) {
					draft.GitInstances[i].Git.GithubToken = ""
					break
				}
			}
		} else {
			draft.Git.GithubToken = ""
		}
	}

	gitPortRaw := strings.TrimSpace(r.FormValue("gitPort"))
	fallbackPort := cfg.Ports.Git
	if isInstance {
		for _, it := range cfg.GitInstances {
			if strings.EqualFold(strings.TrimSpace(it.ID), instanceID) {
				fallbackPort = it.Port
				break
			}
		}
	}
	gitPort, err := parsePort(gitPortRaw, fallbackPort)
	if err != nil {
		s.renderGitForm(w, r, st, draft, instanceID, "", s.errText(r, err), gitPortRaw, r.FormValue("replaceDictJson"))
		return
	}
	if isInstance {
		for i := range draft.GitInstances {
			if strings.EqualFold(strings.TrimSpace(draft.GitInstances[i].ID), instanceID) {
				draft.GitInstances[i].Port = gitPort
				break
			}
		}
	} else {
		draft.Ports.Git = gitPort
	}

	if githubAuthScheme != "token" && githubAuthScheme != "Bearer" {
		s.renderGitForm(w, r, st, draft, instanceID, "", s.t(r, "error.git.authSchemeInvalid"), gitPortRaw, r.FormValue("replaceDictJson"))
		return
	}

	if corsAllowCredentials && corsOrigin == "*" {
		s.renderGitForm(w, r, st, draft, instanceID, "", s.t(r, "error.git.corsCredentialsStar"), gitPortRaw, r.FormValue("replaceDictJson"))
		return
	}

	replaceDictRaw := r.FormValue("replaceDictJson")
	replaceDict, err := parseStringMapJSON(replaceDictRaw)
	if err != nil {
		s.renderGitForm(w, r, st, draft, instanceID, "", fmt.Sprintf("REPLACE_DICT: %v", err), gitPortRaw, replaceDictRaw)
		return
	}
	if isInstance {
		for i := range draft.GitInstances {
			if strings.EqualFold(strings.TrimSpace(draft.GitInstances[i].ID), instanceID) {
				draft.GitInstances[i].Git.ReplaceDict = replaceDict
				break
			}
		}
	} else {
		draft.Git.ReplaceDict = replaceDict
	}

	note := strings.TrimSpace(r.FormValue("note"))
	userID := st.User.ID

	clearSecrets := []string{}
	if clearGithubToken {
		if isInstance {
			clearSecrets = append(clearSecrets, "gitInstances."+instanceID+".git.githubToken")
		} else {
			clearSecrets = append(clearSecrets, "git.githubToken")
		}
	}

	err = s.config.Update(storage.UpdateRequest{
		UserID:               &userID,
		Note:                 noteIfEmpty(note, "edit:git"),
		PreserveEmptySecrets: true,
		ClearSecrets:         clearSecrets,
		Updater: func(cur model.AppConfig) (model.AppConfig, error) {
			next := cur
			applyGit := func(g *model.GitConfig) {
				g.Disabled = !serviceEnabled
				g.Upstream = upstream
				g.UpstreamMobile = upstreamMobile
				g.UpstreamPath = upstreamPath
				g.HTTPS = httpsEnabled
				g.GithubAuthScheme = githubAuthScheme
				g.DisableCache = disableCache
				g.CacheControl = cacheControl
				g.CacheControlMedia = cacheControlMedia
				g.CacheControlText = cacheControlText
				g.CorsOrigin = corsOrigin
				g.CorsAllowCredentials = corsAllowCredentials
				g.CorsExposeHeaders = corsExposeHeaders
				g.BlockedRegions = blockedRegions
				g.BlockedIpAddresses = blockedIPs
				g.ReplaceDict = replaceDict
				if clearGithubToken {
					g.GithubToken = ""
				} else {
					g.GithubToken = githubToken
				}
			}

			if isInstance {
				found := false
				for i := range next.GitInstances {
					if strings.EqualFold(strings.TrimSpace(next.GitInstances[i].ID), instanceID) {
						found = true
						next.GitInstances[i].Port = gitPort
						applyGit(&next.GitInstances[i].Git)
						break
					}
				}
				if !found {
					return model.AppConfig{}, errI18n("error.git.instanceNotFound", instanceID)
				}
			} else {
				next.Ports.Git = gitPort
				applyGit(&next.Git)
			}
			return next, nil
		},
	})
	if err != nil {
		s.renderGitForm(w, r, st, draft, instanceID, "", s.errText(r, err), gitPortRaw, replaceDictRaw)
		return
	}

	if isInstance {
		http.Redirect(w, r, "/config/git?ok=1&instance="+url.QueryEscape(instanceID), http.StatusFound)
	} else {
		http.Redirect(w, r, "/config/git?ok=1", http.StatusFound)
	}
}

func (s *server) renderGitForm(w http.ResponseWriter, r *http.Request, st *reqState, cfg model.AppConfig, instanceID, notice, errMsg, gitPortValue, replaceDictRaw string) {
	instanceID = strings.TrimSpace(instanceID)
	isDefault := instanceID == "" || strings.EqualFold(instanceID, "default")

	defaultName := s.t(r, "common.default")

	currentID := ""
	currentName := defaultName
	currentPort := cfg.Ports.Git
	currentPortKey := "ports.git"
	currentCfg := cfg.Git
	currentEnabled := !cfg.Git.Disabled

	if !isDefault {
		found := false
		for _, it := range cfg.GitInstances {
			id := strings.TrimSpace(it.ID)
			if id == "" {
				continue
			}
			if !strings.EqualFold(id, instanceID) {
				continue
			}

			currentID = id
			currentName = strings.TrimSpace(it.Name)
			if currentName == "" {
				currentName = id
			}
			currentPort = it.Port
			currentPortKey = "gitInstances." + id + ".port"
			currentCfg = it.Git
			currentEnabled = !it.Git.Disabled
			found = true
			break
		}

		if !found {
			if strings.TrimSpace(errMsg) == "" {
				errMsg = s.t(r, "error.git.instanceNotFound", instanceID)
			}
			isDefault = true
			instanceID = ""
		}
	}

	if isDefault {
		currentID = ""
		currentName = defaultName
		currentPort = cfg.Ports.Git
		currentPortKey = "ports.git"
		currentCfg = cfg.Git
		currentEnabled = !cfg.Git.Disabled
	}

	replaceDictJSON := ""
	if strings.TrimSpace(replaceDictRaw) != "" {
		replaceDictJSON = replaceDictRaw
	} else {
		pretty, _ := json.MarshalIndent(currentCfg.ReplaceDict, "", "  ")
		replaceDictJSON = string(pretty)
	}

	authScheme := currentCfg.GithubAuthScheme
	if strings.TrimSpace(authScheme) == "" {
		authScheme = "token"
	}

	gitBaseURL := baseURLForPort(r, currentPort)
	gitSt := func() serviceStatus {
		if !currentEnabled {
			return disabledServiceStatus(currentPort)
		}
		return checkServiceStatus(r.Context(), currentPort)
	}()

	if strings.TrimSpace(gitPortValue) == "" {
		gitPortValue = strconv.Itoa(currentPort)
	}

	instances := make([]gitInstanceRow, 0, 1+len(cfg.GitInstances))
	instances = append(instances, func() gitInstanceRow {
		port := cfg.Ports.Git
		baseURL := baseURLForPort(r, port)
		enabled := !cfg.Git.Disabled
		st := func() serviceStatus {
			if !enabled {
				return disabledServiceStatus(port)
			}
			return checkServiceStatus(r.Context(), port)
		}()
		return gitInstanceRow{
			ID:        "default",
			Name:      defaultName,
			Port:      port,
			Enabled:   enabled,
			BaseURL:   baseURL,
			HealthURL: "/_hazuki/health/git",
			Status:    st,
		}
	}())

	if len(cfg.GitInstances) > 0 {
		sorted := append([]model.GitInstanceConfig(nil), cfg.GitInstances...)
		sort.Slice(sorted, func(i, j int) bool {
			return strings.ToLower(strings.TrimSpace(sorted[i].ID)) < strings.ToLower(strings.TrimSpace(sorted[j].ID))
		})

		for _, it := range sorted {
			id := strings.TrimSpace(it.ID)
			if id == "" {
				continue
			}
			baseURL := baseURLForPort(r, it.Port)
			enabled := !it.Git.Disabled
			st := func() serviceStatus {
				if !enabled {
					return disabledServiceStatus(it.Port)
				}
				return checkServiceStatus(r.Context(), it.Port)
			}()

			name := strings.TrimSpace(it.Name)
			if name == "" {
				name = id
			}
			instances = append(instances, gitInstanceRow{
				ID:        id,
				Name:      name,
				Port:      it.Port,
				Enabled:   enabled,
				BaseURL:   baseURL,
				HealthURL: "/_hazuki/health/git/" + url.PathEscape(id),
				Status:    st,
			})
		}
	}

	gitHealthURL := "/_hazuki/health/git"
	if strings.TrimSpace(currentID) != "" {
		gitHealthURL = "/_hazuki/health/git/" + url.PathEscape(strings.TrimSpace(currentID))
	}

	s.render(w, r, gitData{
		layoutData: layoutData{
			Title:        s.t(r, "page.git.title"),
			BodyTemplate: "git",
			User:         st.User,
			HasUsers:     st.HasUsers,
			Notice:       notice,
			Error:        errMsg,
		},
		Git:               currentCfg,
		GitPort:           currentPort,
		GitPortValue:      gitPortValue,
		GitPortKey:        currentPortKey,
		GitEnabled:        currentEnabled,
		TokenIsSet:        strings.TrimSpace(currentCfg.GithubToken) != "",
		AuthScheme:        authScheme,
		BlockedRegionsCsv: strings.Join(currentCfg.BlockedRegions, ","),
		BlockedIPsCsv:     strings.Join(currentCfg.BlockedIpAddresses, ","),
		ReplaceDictJson:   replaceDictJSON,
		GitBaseURL:        gitBaseURL,
		GitHealthURL:      gitHealthURL,
		GitStatus:         gitSt,

		CurrentInstanceID:   currentID,
		CurrentInstanceName: currentName,
		Instances:           instances,
	})
}
