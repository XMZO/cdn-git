package admin

import (
	"net/http"
	"strconv"
	"strings"

	"hazuki-go/internal/model"
	"hazuki-go/internal/storage"
)

func (s *server) configSakuyaOplist(w http.ResponseWriter, r *http.Request) {
	st := getState(r.Context())
	title := s.t(r, "page.sakuya.oplist.title")
	cfg, err := s.config.GetDecryptedConfig()
	if err != nil {
		s.render(w, r, sakuyaOplistData{
			layoutData: layoutData{
				Title:        title,
				BodyTemplate: "sakuya_oplist",
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
		s.renderSakuyaOplistForm(w, r, st, cfg, notice, "", "", "", "", "")
		return
	case http.MethodPost:
		// continue
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		s.renderSakuyaOplistForm(w, r, st, cfg, "", s.t(r, "error.badRequest"), "", "", "", "")
		return
	}

	curEnabled := !cfg.Sakuya.Disabled && !cfg.Sakuya.Oplist.Disabled &&
		strings.TrimSpace(cfg.Sakuya.Oplist.Address) != "" &&
		strings.TrimSpace(cfg.Sakuya.Oplist.Token) != ""
	serviceEnabled := parseBool(r.FormValue("serviceEnabled"), curEnabled)

	address := strings.TrimSpace(r.FormValue("oplistAddress"))
	publicURL := strings.TrimSpace(r.FormValue("oplistPublicUrl"))

	token := r.FormValue("oplistToken")
	clearToken := parseBool(r.FormValue("clearOplistToken"), false)

	redacted, _ := s.config.GetRedactedConfig()
	tokenIsSet := strings.TrimSpace(cfg.Sakuya.Oplist.Token) != ""
	if !tokenIsSet && strings.TrimSpace(redacted.Sakuya.Oplist.Token) != "" {
		tokenIsSet = true
	}

	if serviceEnabled {
		if address == "" {
			s.renderSakuyaOplistForm(w, r, st, cfg, "", s.t(r, "error.configInvalid"), r.FormValue("sakuyaPort"), address, publicURL, "")
			return
		}
		if !tokenIsSet && strings.TrimSpace(token) == "" && !clearToken {
			s.renderSakuyaOplistForm(w, r, st, cfg, "", s.t(r, "error.configInvalid"), r.FormValue("sakuyaPort"), address, publicURL, "")
			return
		}
	}

	portFallback := cfg.Ports.Sakuya
	if portFallback == 0 {
		portFallback = 3200
	}
	portRaw := strings.TrimSpace(r.FormValue("sakuyaPort"))
	port, err := parsePort(portRaw, portFallback)
	if err != nil {
		s.renderSakuyaOplistForm(w, r, st, cfg, "", s.errText(r, err), portRaw, address, publicURL, "")
		return
	}

	userID := st.User.ID
	clearSecrets := []string{}
	if clearToken {
		clearSecrets = append(clearSecrets, "sakuya.oplist.token")
	}

	err = s.config.Update(storage.UpdateRequest{
		UserID:               &userID,
		Note:                 "edit:sakuya:oplist",
		PreserveEmptySecrets: true,
		ClearSecrets:         clearSecrets,
		Updater: func(cur model.AppConfig) (model.AppConfig, error) {
			next := cur
			next.Ports.Sakuya = port
			next.Sakuya.Disabled = false
			next.Sakuya.Oplist.Disabled = !serviceEnabled
			next.Sakuya.Oplist.Address = address
			next.Sakuya.Oplist.PublicURL = publicURL
			if clearToken {
				next.Sakuya.Oplist.Token = ""
			} else {
				next.Sakuya.Oplist.Token = token
			}
			return next, nil
		},
	})
	if err != nil {
		draft := cfg
		draft.Ports.Sakuya = port
		draft.Sakuya.Disabled = false
		draft.Sakuya.Oplist.Disabled = !serviceEnabled
		draft.Sakuya.Oplist.Address = address
		draft.Sakuya.Oplist.PublicURL = publicURL
		s.renderSakuyaOplistForm(w, r, st, draft, "", s.errText(r, err), portRaw, address, publicURL, "")
		return
	}

	http.Redirect(w, r, "/config/sakuya/oplist?ok=1", http.StatusFound)
}

func (s *server) configSakuyaOneDrive(w http.ResponseWriter, r *http.Request) {
	// Backward-compatible: the OneDrive sub-page is removed.
	http.Redirect(w, r, "/config/sakuya/oplist", http.StatusFound)
}

func (s *server) renderSakuyaOplistForm(w http.ResponseWriter, r *http.Request, st *reqState, cfg model.AppConfig, notice, errMsg, sakuyaPortValue, oplistAddressValue, oplistPublicURLValue, oplistTokenValue string) {
	if strings.TrimSpace(sakuyaPortValue) == "" {
		port := cfg.Ports.Sakuya
		if port == 0 {
			port = 3200
		}
		sakuyaPortValue = strconv.Itoa(port)
	}
	if strings.TrimSpace(oplistAddressValue) == "" {
		oplistAddressValue = cfg.Sakuya.Oplist.Address
	}
	if strings.TrimSpace(oplistPublicURLValue) == "" {
		oplistPublicURLValue = cfg.Sakuya.Oplist.PublicURL
	}

	redacted, _ := s.config.GetRedactedConfig()
	tokenIsSet := strings.TrimSpace(cfg.Sakuya.Oplist.Token) != ""
	if !tokenIsSet && strings.TrimSpace(redacted.Sakuya.Oplist.Token) != "" {
		tokenIsSet = true
	}

	port := cfg.Ports.Sakuya
	if port == 0 {
		port = 3200
	}
	baseURL := baseURLForPort(r, port)
	sakuyaSt := func() serviceStatus {
		if cfg.Sakuya.Disabled || cfg.Sakuya.Oplist.Disabled || strings.TrimSpace(cfg.Sakuya.Oplist.Address) == "" || strings.TrimSpace(cfg.Sakuya.Oplist.Token) == "" {
			return disabledServiceStatus(port)
		}
		return checkServiceStatus(r.Context(), port)
	}()

	s.render(w, r, sakuyaOplistData{
		layoutData: layoutData{
			Title:        s.t(r, "page.sakuya.oplist.title"),
			BodyTemplate: "sakuya_oplist",
			User:         st.User,
			HasUsers:     st.HasUsers,
			Notice:       notice,
			Error:        errMsg,
		},
		Sakuya: cfg.Sakuya,

		SakuyaPort:      port,
		SakuyaPortValue: sakuyaPortValue,

		OplistAddressValue:   oplistAddressValue,
		OplistPublicURLValue: oplistPublicURLValue,

		TokenIsSet: tokenIsSet,
		TokenValue: strings.TrimSpace(oplistTokenValue),

		SakuyaBaseURL:   baseURL,
		SakuyaHealthURL: "/_hazuki/health/sakuya",
		SakuyaStatus:    sakuyaSt,
	})
}
