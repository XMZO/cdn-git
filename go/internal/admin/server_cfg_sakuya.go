package admin

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/url"
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

	instanceID := strings.TrimSpace(r.URL.Query().Get("instance"))

	switch r.Method {
	case http.MethodGet:
		notice := ""
		if r.URL.Query().Get("added") != "" {
			notice = s.t(r, "sakuya.instances.created")
		} else if r.URL.Query().Get("ok") != "" {
			notice = s.t(r, "common.saved")
		}
		s.renderSakuyaOplistForm(w, r, st, cfg, instanceID, notice, "", "", "", "", "", "", false)
		return
	case http.MethodPost:
		// continue
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		s.renderSakuyaOplistForm(w, r, st, cfg, instanceID, "", s.t(r, "error.badRequest"), "", "", "", "", "", false)
		return
	}

	action := strings.TrimSpace(r.FormValue("action"))
	if action == "addInstance" {
		prefix := strings.TrimSpace(r.FormValue("newInstancePrefix"))
		prefix = strings.Trim(prefix, "/\\")
		name := strings.TrimSpace(r.FormValue("newInstanceName"))
		ignoreDup := parseBool(r.FormValue("ignoreDuplicatePrefix"), false)

		if prefix == "" {
			s.renderSakuyaOplistForm(w, r, st, cfg, "", "", s.t(r, "error.sakuya.prefixRequired"), "", "", "", "", "", ignoreDup)
			return
		}

		// Best-effort duplicate check; can be bypassed.
		if !ignoreDup && hasSakuyaPrefixDup(cfg, "", prefix) {
			s.renderSakuyaOplistForm(w, r, st, cfg, "", "", s.t(r, "error.sakuya.prefixDuplicated", prefix), "", prefix, "", "", "", ignoreDup)
			return
		}

		newID, err := newSakuyaInstanceID()
		if err != nil {
			s.renderSakuyaOplistForm(w, r, st, cfg, "", "", s.t(r, "error.internal"), "", prefix, "", "", "", ignoreDup)
			return
		}

		userID := st.User.ID
		err = s.config.Update(storage.UpdateRequest{
			UserID: &userID,
			Note:   "add:sakuya:instance",
			Updater: func(cur model.AppConfig) (model.AppConfig, error) {
				next := cur
				for _, it := range next.Sakuya.Instances {
					if strings.EqualFold(strings.TrimSpace(it.ID), newID) {
						return model.AppConfig{}, errI18n("error.sakuya.instanceExists", newID)
					}
				}

				next.Sakuya.Instances = append(next.Sakuya.Instances, model.SakuyaOplistInstance{
					ID:       newID,
					Name:     name,
					Disabled: true,
					Prefix:   prefix,
				})
				return next, nil
			},
		})
		if err != nil {
			s.renderSakuyaOplistForm(w, r, st, cfg, "", "", s.errText(r, err), "", prefix, "", "", "", ignoreDup)
			return
		}
		http.Redirect(w, r, "/config/sakuya/oplist?ok=1&added=1&instance="+url.QueryEscape(newID), http.StatusFound)
		return
	}
	if action == "deleteInstance" {
		delID := strings.TrimSpace(r.FormValue("instanceID"))
		if delID == "" {
			s.renderSakuyaOplistForm(w, r, st, cfg, "", "", s.t(r, "error.badRequest"), "", "", "", "", "", false)
			return
		}

		userID := st.User.ID
		err = s.config.Update(storage.UpdateRequest{
			UserID: &userID,
			Note:   "delete:sakuya:instance",
			Updater: func(cur model.AppConfig) (model.AppConfig, error) {
				next := cur
				out := make([]model.SakuyaOplistInstance, 0, len(next.Sakuya.Instances))
				found := false
				for _, it := range next.Sakuya.Instances {
					if strings.EqualFold(strings.TrimSpace(it.ID), delID) {
						found = true
						continue
					}
					out = append(out, it)
				}
				if !found {
					return model.AppConfig{}, errI18n("error.sakuya.instanceNotFound", delID)
				}
				next.Sakuya.Instances = out
				return next, nil
			},
		})
		if err != nil {
			s.renderSakuyaOplistForm(w, r, st, cfg, "", "", s.errText(r, err), "", "", "", "", "", false)
			return
		}
		http.Redirect(w, r, "/config/sakuya/oplist?ok=1", http.StatusFound)
		return
	}

	// Default or instance config update.
	instanceID = strings.TrimSpace(r.FormValue("instanceID"))
	isInstance := instanceID != ""

	globalEnabledFallback := !cfg.Sakuya.Disabled
	globalEnabled := parseBool(r.FormValue("sakuyaEnabled"), globalEnabledFallback)

	curEnabled := false
	if isInstance {
		for _, it := range cfg.Sakuya.Instances {
			if strings.EqualFold(strings.TrimSpace(it.ID), instanceID) {
				curEnabled = !it.Disabled
				break
			}
		}
	} else {
		curEnabled = !cfg.Sakuya.Oplist.Disabled
	}
	serviceEnabled := parseBool(r.FormValue("serviceEnabled"), curEnabled)

	address := strings.TrimSpace(r.FormValue("oplistAddress"))
	publicURL := strings.TrimSpace(r.FormValue("oplistPublicUrl"))

	prefix := strings.TrimSpace(r.FormValue("oplistPrefix"))
	prefix = strings.Trim(prefix, "/\\")
	ignoreDup := parseBool(r.FormValue("ignoreDuplicatePrefix"), false)

	token := r.FormValue("oplistToken")
	clearToken := parseBool(r.FormValue("clearOplistToken"), false)

	tokenIsSet := false
	if isInstance {
		for _, it := range cfg.Sakuya.Instances {
			if strings.EqualFold(strings.TrimSpace(it.ID), instanceID) {
				tokenIsSet = strings.TrimSpace(it.Token) != ""
				break
			}
		}
	} else {
		tokenIsSet = strings.TrimSpace(cfg.Sakuya.Oplist.Token) != ""
	}

	if globalEnabled && serviceEnabled {
		if isInstance && prefix == "" {
			s.renderSakuyaOplistForm(w, r, st, cfg, instanceID, "", s.t(r, "error.sakuya.prefixRequired"), r.FormValue("sakuyaPort"), prefix, address, publicURL, "", ignoreDup)
			return
		}
		if address == "" {
			s.renderSakuyaOplistForm(w, r, st, cfg, instanceID, "", s.t(r, "error.configInvalid"), r.FormValue("sakuyaPort"), prefix, address, publicURL, "", ignoreDup)
			return
		}
		if !tokenIsSet && strings.TrimSpace(token) == "" && !clearToken {
			s.renderSakuyaOplistForm(w, r, st, cfg, instanceID, "", s.t(r, "error.configInvalid"), r.FormValue("sakuyaPort"), prefix, address, publicURL, "", ignoreDup)
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
		s.renderSakuyaOplistForm(w, r, st, cfg, instanceID, "", s.errText(r, err), portRaw, prefix, address, publicURL, "", ignoreDup)
		return
	}

	if globalEnabled && serviceEnabled && isInstance && !ignoreDup && hasSakuyaPrefixDup(cfg, instanceID, prefix) {
		s.renderSakuyaOplistForm(w, r, st, cfg, instanceID, "", s.t(r, "error.sakuya.prefixDuplicated", prefix), portRaw, prefix, address, publicURL, "", ignoreDup)
		return
	}

	userID := st.User.ID
	clearSecrets := []string{}
	if clearToken {
		if isInstance {
			clearSecrets = append(clearSecrets, "sakuya.instances."+instanceID+".token")
		} else {
			clearSecrets = append(clearSecrets, "sakuya.oplist.token")
		}
	}

	err = s.config.Update(storage.UpdateRequest{
		UserID:               &userID,
		Note:                 "edit:sakuya:oplist",
		PreserveEmptySecrets: true,
		ClearSecrets:         clearSecrets,
		Updater: func(cur model.AppConfig) (model.AppConfig, error) {
			next := cur
			next.Ports.Sakuya = port
			next.Sakuya.Disabled = !globalEnabled
			if isInstance {
				found := false
				for i := range next.Sakuya.Instances {
					if !strings.EqualFold(strings.TrimSpace(next.Sakuya.Instances[i].ID), instanceID) {
						continue
					}
					found = true
					next.Sakuya.Instances[i].Disabled = !serviceEnabled
					next.Sakuya.Instances[i].Prefix = prefix
					next.Sakuya.Instances[i].Address = address
					next.Sakuya.Instances[i].PublicURL = publicURL
					if clearToken {
						next.Sakuya.Instances[i].Token = ""
					} else {
						next.Sakuya.Instances[i].Token = token
					}
					break
				}
				if !found {
					return model.AppConfig{}, errI18n("error.sakuya.instanceNotFound", instanceID)
				}
			} else {
				next.Sakuya.Oplist.Disabled = !serviceEnabled
				next.Sakuya.Oplist.Address = address
				next.Sakuya.Oplist.PublicURL = publicURL
				if clearToken {
					next.Sakuya.Oplist.Token = ""
				} else {
					next.Sakuya.Oplist.Token = token
				}
			}
			return next, nil
		},
	})
	if err != nil {
		draft := cfg
		draft.Ports.Sakuya = port
		draft.Sakuya.Disabled = !globalEnabled
		if isInstance {
			for i := range draft.Sakuya.Instances {
				if strings.EqualFold(strings.TrimSpace(draft.Sakuya.Instances[i].ID), instanceID) {
					draft.Sakuya.Instances[i].Disabled = !serviceEnabled
					draft.Sakuya.Instances[i].Prefix = prefix
					draft.Sakuya.Instances[i].Address = address
					draft.Sakuya.Instances[i].PublicURL = publicURL
					break
				}
			}
		} else {
			draft.Sakuya.Oplist.Disabled = !serviceEnabled
			draft.Sakuya.Oplist.Address = address
			draft.Sakuya.Oplist.PublicURL = publicURL
		}
		s.renderSakuyaOplistForm(w, r, st, draft, instanceID, "", s.errText(r, err), portRaw, prefix, address, publicURL, "", ignoreDup)
		return
	}

	if isInstance {
		http.Redirect(w, r, "/config/sakuya/oplist?ok=1&instance="+url.QueryEscape(instanceID), http.StatusFound)
	} else {
		http.Redirect(w, r, "/config/sakuya/oplist?ok=1", http.StatusFound)
	}
}

func (s *server) configSakuyaOneDrive(w http.ResponseWriter, r *http.Request) {
	// Backward-compatible: the OneDrive sub-page is removed.
	http.Redirect(w, r, "/config/sakuya/oplist", http.StatusFound)
}

func (s *server) renderSakuyaOplistForm(w http.ResponseWriter, r *http.Request, st *reqState, cfg model.AppConfig, instanceID, notice, errMsg, sakuyaPortValue, oplistPrefixValue, oplistAddressValue, oplistPublicURLValue, oplistTokenValue string, ignoreDup bool) {
	instanceID = strings.TrimSpace(instanceID)
	isDefault := instanceID == "" || strings.EqualFold(instanceID, "default")

	if strings.TrimSpace(sakuyaPortValue) == "" {
		port := cfg.Ports.Sakuya
		if port == 0 {
			port = 3200
		}
		sakuyaPortValue = strconv.Itoa(port)
	}

	port := cfg.Ports.Sakuya
	if port == 0 {
		port = 3200
	}

	currentID := ""
	currentName := s.t(r, "common.default")
	currentPrefix := ""
	currentEnabled := false
	sakuyaEnabledFallback := !cfg.Sakuya.Disabled
	currentAddr := ""
	currentPubURL := ""
	currentTokenIsSet := false

	if isDefault {
		currentID = ""
		currentName = s.t(r, "common.default")
		currentPrefix = ""
		currentEnabled = !cfg.Sakuya.Oplist.Disabled
		currentAddr = cfg.Sakuya.Oplist.Address
		currentPubURL = cfg.Sakuya.Oplist.PublicURL
		currentTokenIsSet = strings.TrimSpace(cfg.Sakuya.Oplist.Token) != ""
	} else {
		found := false
		for _, it := range cfg.Sakuya.Instances {
			id := strings.TrimSpace(it.ID)
			if id == "" || !strings.EqualFold(id, instanceID) {
				continue
			}
			found = true
			currentID = id
			currentName = strings.TrimSpace(it.Name)
			if currentName == "" {
				currentName = strings.TrimSpace(it.Prefix)
			}
			if currentName == "" {
				currentName = id
			}
			currentPrefix = strings.TrimSpace(it.Prefix)
			currentEnabled = !it.Disabled
			currentAddr = it.Address
			currentPubURL = it.PublicURL
			currentTokenIsSet = strings.TrimSpace(it.Token) != ""
			break
		}
		if !found {
			if strings.TrimSpace(errMsg) == "" {
				errMsg = s.t(r, "error.sakuya.instanceNotFound", instanceID)
			}
			isDefault = true
			currentID = ""
			currentName = s.t(r, "common.default")
			currentPrefix = ""
			currentEnabled = !cfg.Sakuya.Oplist.Disabled
			currentAddr = cfg.Sakuya.Oplist.Address
			currentPubURL = cfg.Sakuya.Oplist.PublicURL
			currentTokenIsSet = strings.TrimSpace(cfg.Sakuya.Oplist.Token) != ""
		}
	}

	if strings.TrimSpace(oplistPrefixValue) == "" {
		oplistPrefixValue = currentPrefix
	}
	if strings.TrimSpace(oplistAddressValue) == "" {
		oplistAddressValue = currentAddr
	}
	if strings.TrimSpace(oplistPublicURLValue) == "" {
		oplistPublicURLValue = currentPubURL
	}

	instances := make([]sakuyaInstanceRow, 0, 1+len(cfg.Sakuya.Instances))
	instances = append(instances, func() sakuyaInstanceRow {
		base := baseURLForPort(r, port)
		name := s.t(r, "common.default")
		enabled := !cfg.Sakuya.Disabled && !cfg.Sakuya.Oplist.Disabled &&
			strings.TrimSpace(cfg.Sakuya.Oplist.Address) != "" &&
			strings.TrimSpace(cfg.Sakuya.Oplist.Token) != ""
		addr := strings.TrimSpace(cfg.Sakuya.Oplist.Address)
		if addr == "" {
			addr = "-"
		}
		return sakuyaInstanceRow{
			ID:         "default",
			Name:       name,
			Prefix:     "",
			Enabled:    enabled,
			Address:    addr,
			ServiceURL: base,
		}
	}())
	for _, it := range cfg.Sakuya.Instances {
		id := strings.TrimSpace(it.ID)
		if id == "" {
			continue
		}
		name := strings.TrimSpace(it.Name)
		if name == "" {
			name = strings.TrimSpace(it.Prefix)
		}
		if name == "" {
			name = id
		}
		prefix := strings.TrimSpace(it.Prefix)
		enabled := !cfg.Sakuya.Disabled && !it.Disabled &&
			strings.TrimSpace(it.Address) != "" &&
			strings.TrimSpace(it.Token) != "" &&
			strings.TrimSpace(prefix) != ""

		addr := strings.TrimSpace(it.Address)
		if addr == "" {
			addr = "-"
		}
		base := baseURLForPort(r, port)
		serviceURL := base
		if prefix != "" {
			serviceURL = base + "/" + prefix
		}
		instances = append(instances, sakuyaInstanceRow{
			ID:         id,
			Name:       name,
			Prefix:     prefix,
			Enabled:    enabled,
			Address:    addr,
			ServiceURL: serviceURL,
		})
	}

	isSakuyaActive := func(cfg model.AppConfig) bool {
		if cfg.Sakuya.Disabled {
			return false
		}
		if !cfg.Sakuya.Oplist.Disabled &&
			strings.TrimSpace(cfg.Sakuya.Oplist.Address) != "" &&
			strings.TrimSpace(cfg.Sakuya.Oplist.Token) != "" {
			return true
		}
		for _, it := range cfg.Sakuya.Instances {
			if it.Disabled {
				continue
			}
			if strings.TrimSpace(it.Prefix) == "" || strings.TrimSpace(it.Address) == "" || strings.TrimSpace(it.Token) == "" {
				continue
			}
			return true
		}
		return false
	}

	sakuyaBaseURL := baseURLForPort(r, port)
	if !isDefault && strings.TrimSpace(oplistPrefixValue) != "" {
		sakuyaBaseURL = sakuyaBaseURL + "/" + strings.TrimSpace(oplistPrefixValue)
	}

	sakuyaSt := func() serviceStatus {
		if !isSakuyaActive(cfg) {
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

		CurrentInstanceID:     currentID,
		CurrentInstanceName:   currentName,
		CurrentInstancePrefix: currentPrefix,

		OplistPrefixValue:    strings.TrimSpace(oplistPrefixValue),
		OplistAddressValue:   oplistAddressValue,
		OplistPublicURLValue: oplistPublicURLValue,

		TokenIsSet: currentTokenIsSet,
		TokenValue: strings.TrimSpace(oplistTokenValue),

		SakuyaEnabled:  parseBool(r.FormValue("sakuyaEnabled"), sakuyaEnabledFallback),
		ServiceEnabled: currentEnabled,

		IgnoreDuplicatePrefix: ignoreDup,
		Instances:             instances,

		SakuyaBaseURL:   sakuyaBaseURL,
		SakuyaHealthURL: "/_hazuki/health/sakuya",
		SakuyaStatus:    sakuyaSt,
	})
}

func newSakuyaInstanceID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hasSakuyaPrefixDup(cfg model.AppConfig, ignoreInstanceID string, prefix string) bool {
	needle := strings.ToLower(strings.TrimSpace(strings.Trim(prefix, "/\\")))
	if needle == "" {
		return false
	}
	ignoreInstanceID = strings.ToLower(strings.TrimSpace(ignoreInstanceID))
	for _, it := range cfg.Sakuya.Instances {
		id := strings.ToLower(strings.TrimSpace(it.ID))
		if id == "" || id == ignoreInstanceID {
			continue
		}
		p := strings.ToLower(strings.TrimSpace(strings.Trim(it.Prefix, "/\\")))
		if p != "" && p == needle {
			return true
		}
	}
	return false
}
