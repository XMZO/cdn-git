package admin

import (
	"net/http"
	"strconv"
	"strings"

	"hazuki-go/internal/model"
	"hazuki-go/internal/storage"
)

func (s *server) configPatchouli(w http.ResponseWriter, r *http.Request) {
	st := getState(r.Context())
	title := s.t(r, "page.patchouli.title")

	cfg, err := s.config.GetDecryptedConfig()
	if err != nil {
		s.render(w, r, patchouliData{
			layoutData: layoutData{
				Title:        title,
				BodyTemplate: "patchouli",
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
		s.renderPatchouliForm(w, r, st, cfg, notice, "")
		return
	case http.MethodPost:
		// continue
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		s.renderPatchouliForm(w, r, st, cfg, "", s.t(r, "error.badRequest"))
		return
	}

	port, err := parsePort(r.FormValue("patchouliPort"), cfg.Ports.Patchouli)
	if err != nil {
		s.renderPatchouliForm(w, r, st, cfg, "", s.errText(r, err))
		return
	}

	serviceEnabled := parseBool(r.FormValue("serviceEnabled"), false)
	kind := strings.ToLower(strings.TrimSpace(r.FormValue("kind")))
	if kind == "" {
		kind = "dataset"
	}

	repo := strings.TrimSpace(r.FormValue("repo"))
	revision := strings.TrimSpace(r.FormValue("revision"))
	token := strings.TrimSpace(r.FormValue("token"))
	accessKey := strings.TrimSpace(r.FormValue("accessKey"))

	disableCache := parseBool(r.FormValue("disableCache"), false)

	allowedSuffixes := parseCSV(r.FormValue("allowedRedirectHostSuffixes"))
	allowedSuffixes = filterNonEmpty(allowedSuffixes)

	clearSecrets := make([]string, 0, 2)
	if parseBool(r.FormValue("clearToken"), false) {
		clearSecrets = append(clearSecrets, "patchouli.token")
		token = ""
	}
	if parseBool(r.FormValue("clearAccessKey"), false) {
		clearSecrets = append(clearSecrets, "patchouli.accessKey")
		accessKey = ""
	}

	userID := st.User.ID
	err = s.config.Update(storage.UpdateRequest{
		UserID:               &userID,
		Note:                 "update:patchouli",
		PreserveEmptySecrets: true,
		ClearSecrets:         clearSecrets,
		Updater: func(cur model.AppConfig) (model.AppConfig, error) {
			next := cur
			next.Ports.Patchouli = port
			next.Patchouli.Disabled = !serviceEnabled
			next.Patchouli.Kind = kind
			next.Patchouli.Repo = repo
			next.Patchouli.Revision = revision
			next.Patchouli.Token = token
			next.Patchouli.AccessKey = accessKey
			next.Patchouli.DisableCache = disableCache
			next.Patchouli.AllowedRedirectHostSuffixes = allowedSuffixes
			return next, nil
		},
	})
	if err != nil {
		s.renderPatchouliForm(w, r, st, cfg, "", s.errText(r, err))
		return
	}

	http.Redirect(w, r, "/config/patchouli?ok=1", http.StatusFound)
}

func (s *server) renderPatchouliForm(w http.ResponseWriter, r *http.Request, st *reqState, cfg model.AppConfig, notice string, errText string) {
	port := cfg.Ports.Patchouli
	if port == 0 {
		port = 3201
	}

	baseURL := baseURLForPort(r, port)

	enabled := !cfg.Patchouli.Disabled && strings.TrimSpace(cfg.Patchouli.Repo) != ""
	status := func() serviceStatus {
		if !enabled {
			return disabledServiceStatus(port)
		}
		return checkServiceStatus(r.Context(), port)
	}()

	kind := strings.ToLower(strings.TrimSpace(cfg.Patchouli.Kind))
	if kind == "" {
		kind = "dataset"
	}

	allowedCsv := strings.Join(filterNonEmpty(cfg.Patchouli.AllowedRedirectHostSuffixes), ", ")

	s.render(w, r, patchouliData{
		layoutData: layoutData{
			Title:        s.t(r, "page.patchouli.title"),
			BodyTemplate: "patchouli",
			User:         st.User,
			HasUsers:     st.HasUsers,
			Notice:       notice,
			Error:        errText,
		},
		Patchouli: cfg.Patchouli,

		PatchouliPort:      port,
		PatchouliPortValue: strconv.Itoa(port),

		PatchouliEnabled: enabled,
		TokenIsSet:       strings.TrimSpace(cfg.Patchouli.Token) != "",
		AccessKeyIsSet:   strings.TrimSpace(cfg.Patchouli.AccessKey) != "",

		KindValue:                      kind,
		AllowedRedirectHostSuffixesCsv: allowedCsv,

		PatchouliBaseURL:   baseURL,
		PatchouliHealthURL: "/_hazuki/health/patchouli",
		PatchouliStatus:    status,
	})
}

func filterNonEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, raw := range in {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		out = append(out, s)
	}
	return out
}
