package admin

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"hazuki-go/internal/model"
	"hazuki-go/internal/storage"
)

func (s *server) configCdnjs(w http.ResponseWriter, r *http.Request) {
	st := getState(r.Context())
	title := s.t(r, "page.cdnjs.title")

	cfg, err := s.config.GetDecryptedConfig()
	if err != nil {
		s.render(w, r, cdnjsData{
			layoutData: layoutData{
				Title:        title,
				BodyTemplate: "cdnjs",
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
		s.renderCdnjsForm(
			w,
			r,
			st,
			cfg,
			notice,
			"",
			strconv.Itoa(cfg.Ports.Cdnjs),
			strings.TrimSpace(cfg.Cdnjs.GhUserPolicy),
			strings.Join(cfg.Cdnjs.AllowedGhUsers, ","),
			strings.Join(cfg.Cdnjs.BlockedGhUsers, ","),
			strconv.Itoa(cfg.Cdnjs.Redis.Port),
			"",
			"",
		)
		return
	case http.MethodPost:
		// continue
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		s.renderCdnjsForm(
			w,
			r,
			st,
			cfg,
			"",
			s.t(r, "error.badRequest"),
			strconv.Itoa(cfg.Ports.Cdnjs),
			strings.TrimSpace(cfg.Cdnjs.GhUserPolicy),
			strings.Join(cfg.Cdnjs.AllowedGhUsers, ","),
			strings.Join(cfg.Cdnjs.BlockedGhUsers, ","),
			strconv.Itoa(cfg.Cdnjs.Redis.Port),
			"",
			"",
		)
		return
	}

	draft := cfg
	serviceEnabled := parseBool(r.FormValue("serviceEnabled"), !cfg.Cdnjs.Disabled)
	draft.Cdnjs.Disabled = !serviceEnabled

	assetURL := strings.TrimSpace(r.FormValue("assetUrl"))
	if assetURL == "" {
		assetURL = "https://cdn.jsdelivr.net"
	}
	assetURL = strings.TrimRight(assetURL, "/")
	draft.Cdnjs.AssetURL = assetURL

	defaultUser := strings.TrimSpace(r.FormValue("defaultGhUser"))
	draft.Cdnjs.DefaultGhUser = defaultUser

	ghUserPolicyRaw := strings.TrimSpace(r.FormValue("ghUserPolicy"))
	ghUserPolicy := strings.ToLower(strings.TrimSpace(ghUserPolicyRaw))
	if ghUserPolicy == "" {
		ghUserPolicy = "allowlist"
	}
	if ghUserPolicy != "allowlist" && ghUserPolicy != "denylist" {
		s.renderCdnjsForm(
			w,
			r,
			st,
			draft,
			"",
			s.t(r, "error.cdnjs.ghUserPolicyInvalid"),
			strings.TrimSpace(r.FormValue("cdnjsPort")),
			ghUserPolicyRaw,
			strings.TrimSpace(r.FormValue("allowedGhUsers")),
			strings.TrimSpace(r.FormValue("blockedGhUsers")),
			strings.TrimSpace(r.FormValue("redisPort")),
			strings.TrimSpace(r.FormValue("defaultTTLSeconds")),
			r.FormValue("ttlOverrides"),
		)
		return
	}
	draft.Cdnjs.GhUserPolicy = ghUserPolicy

	allowedUsersRaw := strings.TrimSpace(r.FormValue("allowedGhUsers"))
	allowedUsers := parseCSV(allowedUsersRaw)
	draft.Cdnjs.AllowedGhUsers = allowedUsers

	blockedUsersRaw := strings.TrimSpace(r.FormValue("blockedGhUsers"))
	blockedUsers := parseCSV(blockedUsersRaw)
	draft.Cdnjs.BlockedGhUsers = blockedUsers

	redisHost := strings.TrimSpace(r.FormValue("redisHost"))
	if redisHost == "" {
		redisHost = "redis"
	}
	draft.Cdnjs.Redis.Host = redisHost

	defaultTTLRaw := strings.TrimSpace(r.FormValue("defaultTTLSeconds"))
	ttlOverridesRaw := r.FormValue("ttlOverrides")

	cdnjsPortRaw := strings.TrimSpace(r.FormValue("cdnjsPort"))
	cdnjsPort, err := parsePort(cdnjsPortRaw, cfg.Ports.Cdnjs)
	if err != nil {
		s.renderCdnjsForm(w, r, st, draft, "", s.errText(r, err), cdnjsPortRaw, ghUserPolicyRaw, allowedUsersRaw, blockedUsersRaw, r.FormValue("redisPort"), defaultTTLRaw, ttlOverridesRaw)
		return
	}
	draft.Ports.Cdnjs = cdnjsPort

	u, err := url.Parse(assetURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || strings.TrimSpace(u.Host) == "" {
		s.renderCdnjsForm(w, r, st, draft, "", s.t(r, "error.cdnjs.assetUrlInvalid"), cdnjsPortRaw, ghUserPolicyRaw, allowedUsersRaw, blockedUsersRaw, r.FormValue("redisPort"), defaultTTLRaw, ttlOverridesRaw)
		return
	}

	redisPortRaw := strings.TrimSpace(r.FormValue("redisPort"))
	redisPort, err := parsePort(redisPortRaw, cfg.Cdnjs.Redis.Port)
	if err != nil {
		s.renderCdnjsForm(w, r, st, draft, "", s.errText(r, err), cdnjsPortRaw, ghUserPolicyRaw, allowedUsersRaw, blockedUsersRaw, redisPortRaw, defaultTTLRaw, ttlOverridesRaw)
		return
	}
	draft.Cdnjs.Redis.Port = redisPort

	defaultTTLSeconds, err := parseTTLSeconds(defaultTTLRaw)
	if err != nil {
		s.renderCdnjsForm(w, r, st, draft, "", s.errText(r, err), cdnjsPortRaw, ghUserPolicyRaw, allowedUsersRaw, blockedUsersRaw, redisPortRaw, defaultTTLRaw, ttlOverridesRaw)
		return
	}
	draft.Cdnjs.DefaultTTLSeconds = defaultTTLSeconds

	cacheTTLSeconds, err := parseTTLOverrides(ttlOverridesRaw)
	if err != nil {
		s.renderCdnjsForm(w, r, st, draft, "", s.errText(r, err), cdnjsPortRaw, ghUserPolicyRaw, allowedUsersRaw, blockedUsersRaw, redisPortRaw, defaultTTLRaw, ttlOverridesRaw)
		return
	}
	draft.Cdnjs.CacheTTLSeconds = cacheTTLSeconds

	note := strings.TrimSpace(r.FormValue("note"))
	userID := st.User.ID

	err = s.config.Update(storage.UpdateRequest{
		UserID: &userID,
		Note:   noteIfEmpty(note, "edit:cdnjs"),
		Updater: func(cur model.AppConfig) (model.AppConfig, error) {
			next := cur
			next.Ports.Cdnjs = cdnjsPort
			next.Cdnjs.Disabled = !serviceEnabled
			next.Cdnjs.AssetURL = assetURL
			next.Cdnjs.DefaultGhUser = defaultUser
			next.Cdnjs.GhUserPolicy = ghUserPolicy
			next.Cdnjs.AllowedGhUsers = allowedUsers
			next.Cdnjs.BlockedGhUsers = blockedUsers
			next.Cdnjs.Redis.Host = redisHost
			next.Cdnjs.Redis.Port = redisPort
			next.Cdnjs.DefaultTTLSeconds = defaultTTLSeconds
			next.Cdnjs.CacheTTLSeconds = cacheTTLSeconds
			return next, nil
		},
	})
	if err != nil {
		s.renderCdnjsForm(w, r, st, draft, "", s.errText(r, err), cdnjsPortRaw, ghUserPolicyRaw, allowedUsersRaw, blockedUsersRaw, redisPortRaw, defaultTTLRaw, ttlOverridesRaw)
		return
	}

	http.Redirect(w, r, "/config/cdnjs?ok=1", http.StatusFound)
}
