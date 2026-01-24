package admin

import (
	"fmt"
	"net/http"
	"net/url"
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
