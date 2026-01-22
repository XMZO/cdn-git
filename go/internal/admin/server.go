package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"hazuki-go/internal/i18n"
	"hazuki-go/internal/model"
	"hazuki-go/internal/proxy/cdnjsproxy"
	"hazuki-go/internal/storage"
)

const cookieName = "hazuki_session"
const langCookieName = "hazuki_lang"

type Options struct {
	DB         *sql.DB
	Config     *storage.ConfigStore
	Port       int
	SessionTTL int
}

type server struct {
	db         *sql.DB
	config     *storage.ConfigStore
	port       int
	sessionTTL int
	startedAt  time.Time
}

type reqState struct {
	HasUsers bool
	User     *storage.User
}

type ctxKey string

const stateKey ctxKey = "hazuki_admin_state"

type layoutData struct {
	Title        string
	BodyTemplate string
	User         *storage.User
	HasUsers     bool
	Notice       string
	Error        string

	Lang   string
	JSI18n template.JS
}

type dashboardData struct {
	layoutData
	UpdatedAt string
	Ports     model.PortsConfig
	AdminURL  string

	TorcherinoURL       string
	TorcherinoHealthURL string
	TorcherinoStatus    serviceStatus

	CdnjsURL       string
	CdnjsHealthURL string
	CdnjsStatus    serviceStatus

	GitURL       string
	GitHealthURL string
	GitStatus    serviceStatus
	GitInstances []gitInstanceRow

	CdnjsRedis redisStatus

	Warnings []string
}

type cdnjsData struct {
	layoutData
	Cdnjs             model.CdnjsConfig
	CdnjsPort         int
	CdnjsPortValue    string
	GhUserPolicyValue string
	AllowedUsersCsv   string
	BlockedUsersCsv   string
	RedisPortValue    string
	DefaultTTLValue   string
	TTLOverridesValue string
	TTLEffectiveJSON  template.JS
	CdnjsBaseURL      string
	CdnjsHealthURL    string

	RedisStatus redisStatus
	CdnjsStatus serviceStatus
}

type gitData struct {
	layoutData
	Git               model.GitConfig
	GitPort           int
	GitPortValue      string
	GitPortKey        string
	GitEnabled        bool
	TokenIsSet        bool
	AuthScheme        string
	BlockedRegionsCsv string
	BlockedIPsCsv     string
	ReplaceDictJson   string
	GitBaseURL        string
	GitHealthURL      string
	GitStatus         serviceStatus

	CurrentInstanceID   string
	CurrentInstanceName string
	Instances           []gitInstanceRow
}

type gitInstanceRow struct {
	ID        string
	Name      string
	Port      int
	Enabled   bool
	BaseURL   string
	HealthURL string
	Status    serviceStatus
}

type torcherinoData struct {
	layoutData
	Torcherino model.TorcherinoConfig

	TorcherinoPort      int
	TorcherinoPortValue string

	DefaultTargetValue string
	HostMappingJSON    string

	SecretIsSet                    bool
	WorkerSecretKeyValue           string
	WorkerSecretHeadersCsvValue    string
	WorkerSecretHeaderMapJSONValue string

	TorcherinoBaseURL   string
	TorcherinoHealthURL string
	TorcherinoStatus    serviceStatus
}

type accountData struct {
	layoutData
}

type versionsData struct {
	layoutData
	Versions []storage.ConfigVersion
}

type importData struct {
	layoutData
	ConfigJSON string
}

type systemData struct {
	layoutData

	GoVersion         string
	BuildVersion      string
	Uptime            string
	StartedAt         string
	Now               string
	SessionTTLSeconds int
	EncryptionEnabled bool
	ConfigUpdatedAt   string

	DBPath        string
	DBSize        string
	UsersCount    int
	VersionsCount int64
	SessionsCount int64

	Ports model.PortsConfig

	AdminStatus      serviceStatus
	TorcherinoStatus serviceStatus
	CdnjsStatus      serviceStatus
	GitStatus        serviceStatus

	Redis redisStatus
}

type wizardData struct {
	layoutData

	TokenIsSet  bool
	SecretIsSet bool

	TorcherinoDefaultTarget         string
	TorcherinoHostMappingJSON       string
	TorcherinoWorkerSecretKey       string
	TorcherinoWorkerSecretHeaders   string
	TorcherinoWorkerSecretHeaderMap string

	CdnjsDefaultGhUser  string
	CdnjsAllowedGhUsers string
	CdnjsGhUserPolicy   string
	CdnjsBlockedGhUsers string
	CdnjsAssetURL       string
	CdnjsRedisHost      string
	CdnjsRedisPort      string

	GitUpstreamPath string
	GitGithubToken  string
}

type redisStatus struct {
	Addr      string
	Status    string // ok | error | disabled
	LatencyMS int64
	Error     string

	ServerVersion    string
	UptimeSeconds    int64
	ConnectedClients int64
	UsedMemoryHuman  string
	DBSize           int64
}

type serviceStatus struct {
	Addr      string
	URL       string
	Service   string
	Status    string // ok | error | disabled
	LatencyMS int64
	Error     string
}

func NewHandler(opts Options) (http.Handler, error) {
	if opts.DB == nil {
		return nil, errors.New("admin: DB is required")
	}
	if opts.Config == nil {
		return nil, errors.New("admin: ConfigStore is required")
	}
	if opts.Port < 1 || opts.Port > 65535 {
		return nil, errors.New("admin: invalid port")
	}
	if opts.SessionTTL <= 0 {
		opts.SessionTTL = 86400
	}

	s := &server{
		db:         opts.DB,
		config:     opts.Config,
		port:       opts.Port,
		sessionTTL: opts.SessionTTL,
		startedAt:  time.Now(),
	}

	// Best-effort cleanup.
	_ = storage.CleanupExpiredSessions(opts.DB)

	mux := http.NewServeMux()
	mux.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(uiAssetsFS))))
	mux.Handle("/favicon.ico", http.RedirectHandler("/assets/fav.png", http.StatusFound))
	mux.Handle("/fav.png", http.RedirectHandler("/assets/fav.png", http.StatusFound))
	mux.HandleFunc("/_hazuki/health", s.wrap(s.health))
	mux.HandleFunc("/setup", s.wrap(s.setup))
	mux.HandleFunc("/login", s.wrap(s.login))
	mux.HandleFunc("/lang", s.wrap(s.setLang))
	mux.HandleFunc("/logout", s.wrapRequireAuth(s.logout))
	mux.HandleFunc("/account", s.wrapRequireAuth(s.account))
	mux.HandleFunc("/account/password", s.wrapRequireAuth(s.accountPassword))
	mux.HandleFunc("/system", s.wrapRequireAuth(s.system))
	mux.HandleFunc("/wizard", s.wrapRequireAuth(s.wizard))
	mux.HandleFunc("/config/git", s.wrapRequireAuth(s.configGit))
	mux.HandleFunc("/config/cdnjs", s.wrapRequireAuth(s.configCdnjs))
	mux.HandleFunc("/config/torcherino", s.wrapRequireAuth(s.configTorcherino))
	mux.HandleFunc("/config/versions", s.wrapRequireAuth(s.configVersions))
	mux.HandleFunc("/config/versions/", s.wrapRequireAuth(s.configVersionsSub))
	mux.HandleFunc("/config/export", s.wrapRequireAuth(s.configExport))
	mux.HandleFunc("/config/import", s.wrapRequireAuth(s.configImport))
	mux.HandleFunc("/", s.wrapRequireAuth(s.dashboard))

	return mux, nil
}

func (s *server) wrap(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st, err := s.buildState(r)
		if err != nil {
			http.Error(w, "Bad gateway", http.StatusBadGateway)
			return
		}

		// If no users exist, force setup (except setup/health).
		if !st.HasUsers && r.URL.Path != "/setup" && r.URL.Path != "/_hazuki/health" {
			http.Redirect(w, r, "/setup", http.StatusFound)
			return
		}

		ctx := context.WithValue(r.Context(), stateKey, st)
		next(w, r.WithContext(ctx))
	}
}

func (s *server) wrapRequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return s.wrap(func(w http.ResponseWriter, r *http.Request) {
		st := getState(r.Context())
		if st == nil || st.User == nil {
			if st != nil && !st.HasUsers {
				http.Redirect(w, r, "/setup", http.StatusFound)
				return
			}
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next(w, r)
	})
}

func (s *server) buildState(r *http.Request) (*reqState, error) {
	count, err := storage.CountUsers(s.db)
	if err != nil {
		return nil, err
	}
	st := &reqState{HasUsers: count > 0}

	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return st, nil
	}
	user, ok, err := storage.GetSessionUser(s.db, cookie.Value)
	if err != nil {
		return nil, err
	}
	if ok {
		st.User = &user
	}
	return st, nil
}

func getState(ctx context.Context) *reqState {
	v := ctx.Value(stateKey)
	st, _ := v.(*reqState)
	return st
}

func (s *server) render(w http.ResponseWriter, r *http.Request, data any) {
	w.Header().Set("content-type", "text/html; charset=utf-8")
	lang := s.pickLang(r)
	data = injectI18nData(data, lang)
	_ = pageTemplates.ExecuteTemplate(w, "layout", data)
}

func (s *server) pickLang(r *http.Request) string {
	if r == nil {
		return i18n.LangZH
	}

	if q := i18n.NormalizeLang(r.URL.Query().Get("lang")); q != "" {
		return q
	}

	if c, err := r.Cookie(langCookieName); err == nil {
		if v := i18n.NormalizeLang(c.Value); v != "" {
			return v
		}
	}

	return i18n.NegotiateLang(r.Header.Get("Accept-Language"), i18n.LangZH)
}

func (s *server) t(r *http.Request, key string, args ...any) string {
	return adminI18n.T(s.pickLang(r), key, args...)
}

type i18nError interface {
	I18n() (string, []any)
}

type errKey struct {
	key  string
	args []any
}

func (e errKey) Error() string { return e.key }

func (e errKey) I18n() (string, []any) { return e.key, e.args }

func errI18n(key string, args ...any) error {
	return errKey{key: key, args: args}
}

func (s *server) errText(r *http.Request, err error) string {
	if err == nil {
		return ""
	}
	var ie i18nError
	if errors.As(err, &ie) {
		key, args := ie.I18n()
		return s.t(r, key, args...)
	}
	return err.Error()
}

func injectI18nData(data any, lang string) any {
	if data == nil {
		return data
	}

	jsMap := adminI18n.Export(lang, "js.")
	jsBytes, _ := json.Marshal(jsMap)

	v := reflect.ValueOf(data)

	// Fast-path: pointer to struct.
	if v.Kind() == reflect.Ptr && !v.IsNil() && v.Elem().Kind() == reflect.Struct {
		if f := v.Elem().FieldByName("Lang"); f.IsValid() && f.CanSet() && f.Kind() == reflect.String {
			f.SetString(lang)
		}
		if f := v.Elem().FieldByName("JSI18n"); f.IsValid() && f.CanSet() {
			if f.Type() == reflect.TypeOf(template.JS("")) {
				f.Set(reflect.ValueOf(template.JS(string(jsBytes))))
			}
		}
		return data
	}

	// Struct value: copy into a new pointer so we can set fields.
	if v.Kind() == reflect.Struct {
		p := reflect.New(v.Type())
		p.Elem().Set(v)
		if f := p.Elem().FieldByName("Lang"); f.IsValid() && f.CanSet() && f.Kind() == reflect.String {
			f.SetString(lang)
		}
		if f := p.Elem().FieldByName("JSI18n"); f.IsValid() && f.CanSet() {
			if f.Type() == reflect.TypeOf(template.JS("")) {
				f.Set(reflect.ValueOf(template.JS(string(jsBytes))))
			}
		}
		return p.Interface()
	}

	return data
}

func (s *server) health(w http.ResponseWriter, r *http.Request) {
	count, _ := storage.CountUsers(s.db)
	payload := map[string]any{
		"ok":                true,
		"service":           "admin",
		"port":              s.port,
		"usersCount":        count,
		"encryptionEnabled": s.config.IsEncryptionEnabled(),
		"updatedAt":         s.config.GetUpdatedAt(),
		"time":              time.Now().UTC().Format(time.RFC3339Nano),
	}
	b, _ := json.MarshalIndent(payload, "", "  ")
	w.Header().Set("content-type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(b)
}

func (s *server) setup(w http.ResponseWriter, r *http.Request) {
	st := getState(r.Context())
	if st == nil {
		http.Error(w, "Bad gateway", http.StatusBadGateway)
		return
	}
	if st.HasUsers {
		if st.User != nil {
			http.Redirect(w, r, "/", http.StatusFound)
		} else {
			http.Redirect(w, r, "/login", http.StatusFound)
		}
		return
	}

	title := s.t(r, "page.setup.title")

	switch r.Method {
	case http.MethodGet:
		s.render(w, r, layoutData{
			Title:        title,
			BodyTemplate: "setup",
			User:         st.User,
			HasUsers:     st.HasUsers,
		})
		return
	case http.MethodPost:
		// continue
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		s.render(w, r, layoutData{
			Title:        title,
			BodyTemplate: "setup",
			User:         st.User,
			HasUsers:     st.HasUsers,
			Error:        s.t(r, "error.badRequest"),
		})
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	_, err := storage.CreateUser(s.db, username, password)
	if err != nil {
		s.render(w, r, layoutData{
			Title:        title,
			BodyTemplate: "setup",
			User:         st.User,
			HasUsers:     st.HasUsers,
			Error:        err.Error(),
		})
		return
	}

	user, ok, err := storage.VerifyUserPassword(s.db, username, password)
	if err != nil || !ok {
		s.render(w, r, layoutData{
			Title:        title,
			BodyTemplate: "setup",
			User:         st.User,
			HasUsers:     st.HasUsers,
			Error:        s.t(r, "error.failedCreateUser"),
		})
		return
	}
	token, err := storage.CreateSession(s.db, user.ID, s.sessionTTL)
	if err != nil {
		s.render(w, r, layoutData{
			Title:        title,
			BodyTemplate: "setup",
			User:         st.User,
			HasUsers:     st.HasUsers,
			Error:        s.t(r, "error.failedCreateSession"),
		})
		return
	}

	setSessionCookie(w, token, s.sessionTTL, isSecureRequest(r))
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	st := getState(r.Context())
	if st == nil {
		http.Error(w, "Bad gateway", http.StatusBadGateway)
		return
	}
	if !st.HasUsers {
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}
	if st.User != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	title := s.t(r, "page.login.title")

	switch r.Method {
	case http.MethodGet:
		s.render(w, r, layoutData{
			Title:        title,
			BodyTemplate: "login",
			User:         st.User,
			HasUsers:     st.HasUsers,
		})
		return
	case http.MethodPost:
		// continue
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		s.render(w, r, layoutData{
			Title:        title,
			BodyTemplate: "login",
			User:         st.User,
			HasUsers:     st.HasUsers,
			Error:        s.t(r, "error.badRequest"),
		})
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")
	user, ok, err := storage.VerifyUserPassword(s.db, username, password)
	if err != nil {
		s.render(w, r, layoutData{
			Title:        title,
			BodyTemplate: "login",
			User:         st.User,
			HasUsers:     st.HasUsers,
			Error:        s.t(r, "error.badRequest"),
		})
		return
	}
	if !ok {
		s.render(w, r, layoutData{
			Title:        title,
			BodyTemplate: "login",
			User:         st.User,
			HasUsers:     st.HasUsers,
			Error:        s.t(r, "error.loginFailed"),
		})
		return
	}
	token, err := storage.CreateSession(s.db, user.ID, s.sessionTTL)
	if err != nil {
		s.render(w, r, layoutData{
			Title:        title,
			BodyTemplate: "login",
			User:         st.User,
			HasUsers:     st.HasUsers,
			Error:        s.t(r, "error.failedCreateSession"),
		})
		return
	}
	setSessionCookie(w, token, s.sessionTTL, isSecureRequest(r))
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *server) setLang(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	next := ""
	if q := strings.TrimSpace(r.URL.Query().Get("next")); q != "" {
		if u, err := url.Parse(q); err == nil && !u.IsAbs() && strings.HasPrefix(u.Path, "/") {
			next = u.String()
		}
	}
	if next == "" {
		if ref := strings.TrimSpace(r.Referer()); ref != "" {
			if u, err := url.Parse(ref); err == nil && strings.EqualFold(u.Host, r.Host) && strings.HasPrefix(u.Path, "/") {
				next = u.RequestURI()
			}
		}
	}
	if next == "" {
		next = "/"
	}

	targetLang := i18n.NormalizeLang(r.URL.Query().Get("to"))
	if targetLang == "" {
		targetLang = i18n.LangZH
	}

	http.SetCookie(w, &http.Cookie{
		Name:     langCookieName,
		Value:    targetLang,
		Path:     "/",
		MaxAge:   31536000,
		Secure:   isSecureRequest(r),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, next, http.StatusFound)
}

func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	st := getState(r.Context())
	if st == nil || st.User == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if cookie, err := r.Cookie(cookieName); err == nil {
		_ = storage.DeleteSession(s.db, cookie.Value)
	}
	clearSessionCookie(w, isSecureRequest(r))
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *server) dashboard(w http.ResponseWriter, r *http.Request) {
	st := getState(r.Context())
	title := s.t(r, "page.dashboard.title")

	cfg, err := s.config.GetDecryptedConfig()
	if err != nil {
		s.render(w, r, dashboardData{
			layoutData: layoutData{
				Title:        title,
				BodyTemplate: "dashboard",
				User:         st.User,
				HasUsers:     st.HasUsers,
				Error:        err.Error(),
			},
		})
		return
	}

	redisSt := checkRedisStatus(r.Context(), cfg.Cdnjs.Redis.Host, cfg.Cdnjs.Redis.Port)

	warnings := make([]string, 0, 8)
	if !s.config.IsEncryptionEnabled() {
		hasSecret := strings.TrimSpace(cfg.Git.GithubToken) != "" ||
			strings.TrimSpace(cfg.Torcherino.WorkerSecretKey) != "" ||
			len(cfg.Torcherino.WorkerSecretHeaderMap) > 0
		if hasSecret {
			warnings = append(warnings, s.t(r, "warning.masterKeyMissing"))
		}
	}

	if !cfg.Cdnjs.Disabled {
		ghUserPolicy := strings.ToLower(strings.TrimSpace(cfg.Cdnjs.GhUserPolicy))
		if ghUserPolicy == "" {
			ghUserPolicy = "allowlist"
		}

		if strings.TrimSpace(cfg.Cdnjs.DefaultGhUser) == "" {
			warnings = append(warnings, s.t(r, "warning.cdnjs.defaultUserMissing"))
		}
		if ghUserPolicy == "denylist" {
			if len(cfg.Cdnjs.BlockedGhUsers) == 0 {
				warnings = append(warnings, s.t(r, "warning.cdnjs.denylistOpen"))
			}
		} else {
			if len(cfg.Cdnjs.AllowedGhUsers) == 0 {
				warnings = append(warnings, s.t(r, "warning.cdnjs.allowlistEmpty"))
			}
		}
		if redisSt.Status == "error" {
			warnings = append(warnings, s.t(r, "warning.cdnjs.redisError"))
		}
	}
	if !cfg.Torcherino.Disabled && strings.TrimSpace(cfg.Torcherino.DefaultTarget) == "" && len(cfg.Torcherino.HostMapping) == 0 {
		warnings = append(warnings, s.t(r, "warning.torcherino.badConfig"))
	}

	scheme := requestScheme(r)
	adminHost := strings.TrimSpace(r.Host)
	adminURL := ""
	if adminHost != "" {
		adminURL = scheme + "://" + adminHost
	}
	torcherinoURL := baseURLForPort(r, cfg.Ports.Torcherino)
	cdnjsURL := baseURLForPort(r, cfg.Ports.Cdnjs)
	gitURL := baseURLForPort(r, cfg.Ports.Git)

	gitInstances := []gitInstanceRow{}
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
			name := strings.TrimSpace(it.Name)
			if name == "" {
				name = id
			}
			baseURL := baseURLForPort(r, it.Port)
			enabled := !it.Git.Disabled
			st := func() serviceStatus {
				if !enabled {
					return disabledServiceStatus(it.Port)
				}
				return checkServiceStatus(r.Context(), it.Port)
			}()
			gitInstances = append(gitInstances, gitInstanceRow{
				ID:        id,
				Name:      name,
				Port:      it.Port,
				Enabled:   enabled,
				BaseURL:   baseURL,
				HealthURL: baseURL + "/_hazuki/health",
				Status:    st,
			})
		}
	}

	s.render(w, r, dashboardData{
		layoutData: layoutData{
			Title:        title,
			BodyTemplate: "dashboard",
			User:         st.User,
			HasUsers:     st.HasUsers,
		},
		UpdatedAt: s.config.GetUpdatedAt(),
		Ports:     cfg.Ports,
		AdminURL:  adminURL,

		TorcherinoURL:       torcherinoURL,
		TorcherinoHealthURL: torcherinoURL + "/_hazuki/health",
		TorcherinoStatus: func() serviceStatus {
			if cfg.Torcherino.Disabled {
				return disabledServiceStatus(cfg.Ports.Torcherino)
			}
			return checkServiceStatus(r.Context(), cfg.Ports.Torcherino)
		}(),

		CdnjsURL:       cdnjsURL,
		CdnjsHealthURL: cdnjsURL + "/_hazuki/health",
		CdnjsStatus: func() serviceStatus {
			if cfg.Cdnjs.Disabled {
				return disabledServiceStatus(cfg.Ports.Cdnjs)
			}
			return checkServiceStatus(r.Context(), cfg.Ports.Cdnjs)
		}(),

		GitURL:       gitURL,
		GitHealthURL: gitURL + "/_hazuki/health",
		GitStatus: func() serviceStatus {
			if cfg.Git.Disabled {
				return disabledServiceStatus(cfg.Ports.Git)
			}
			return checkServiceStatus(r.Context(), cfg.Ports.Git)
		}(),
		GitInstances: gitInstances,

		CdnjsRedis: redisSt,
		Warnings:   warnings,
	})
}

func (s *server) system(w http.ResponseWriter, r *http.Request) {
	st := getState(r.Context())
	title := s.t(r, "page.system.title")

	cfg, err := s.config.GetDecryptedConfig()
	if err != nil {
		s.render(w, r, systemData{
			layoutData: layoutData{
				Title:        title,
				BodyTemplate: "system",
				User:         st.User,
				HasUsers:     st.HasUsers,
				Error:        err.Error(),
			},
		})
		return
	}

	usersCount, _ := storage.CountUsers(s.db)

	versionsCount := int64(0)
	_ = s.db.QueryRowContext(r.Context(), "SELECT COUNT(1) FROM config_versions").Scan(&versionsCount)

	sessionsCount := int64(0)
	_ = s.db.QueryRowContext(r.Context(), "SELECT COUNT(1) FROM sessions").Scan(&sessionsCount)

	dbPath := ""
	dbSize := ""
	if p, size, err := getSQLiteMainDBPathAndSize(r.Context(), s.db); err == nil {
		dbPath = p
		dbSize = formatBytes(size)
	}

	buildVersion := "devel"
	if info, ok := debug.ReadBuildInfo(); ok && info != nil && info.Main.Version != "" {
		buildVersion = info.Main.Version
	}

	now := time.Now()

	s.render(w, r, systemData{
		layoutData: layoutData{
			Title:        title,
			BodyTemplate: "system",
			User:         st.User,
			HasUsers:     st.HasUsers,
		},

		GoVersion:         runtime.Version(),
		BuildVersion:      buildVersion,
		Uptime:            time.Since(s.startedAt).Truncate(time.Second).String(),
		StartedAt:         s.startedAt.Format(time.RFC3339),
		Now:               now.Format(time.RFC3339),
		SessionTTLSeconds: s.sessionTTL,

		EncryptionEnabled: s.config.IsEncryptionEnabled(),
		ConfigUpdatedAt:   s.config.GetUpdatedAt(),

		DBPath:        defaultString(dbPath, "(unknown)"),
		DBSize:        defaultString(dbSize, "(unknown)"),
		UsersCount:    usersCount,
		VersionsCount: versionsCount,
		SessionsCount: sessionsCount,

		Ports: cfg.Ports,

		AdminStatus: checkServiceStatus(r.Context(), s.port),
		TorcherinoStatus: func() serviceStatus {
			if cfg.Torcherino.Disabled {
				return disabledServiceStatus(cfg.Ports.Torcherino)
			}
			return checkServiceStatus(r.Context(), cfg.Ports.Torcherino)
		}(),
		CdnjsStatus: func() serviceStatus {
			if cfg.Cdnjs.Disabled {
				return disabledServiceStatus(cfg.Ports.Cdnjs)
			}
			return checkServiceStatus(r.Context(), cfg.Ports.Cdnjs)
		}(),
		GitStatus: func() serviceStatus {
			if cfg.Git.Disabled {
				return disabledServiceStatus(cfg.Ports.Git)
			}
			return checkServiceStatus(r.Context(), cfg.Ports.Git)
		}(),

		Redis: checkRedisStatus(r.Context(), cfg.Cdnjs.Redis.Host, cfg.Cdnjs.Redis.Port),
	})
}

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

func (s *server) account(w http.ResponseWriter, r *http.Request) {
	st := getState(r.Context())
	title := s.t(r, "page.account.title")
	notice := ""
	if r.URL.Query().Get("ok") != "" {
		notice = s.t(r, "common.saved")
	}
	s.render(w, r, accountData{
		layoutData: layoutData{
			Title:        title,
			BodyTemplate: "account",
			User:         st.User,
			HasUsers:     st.HasUsers,
			Notice:       notice,
		},
	})
}

func (s *server) accountPassword(w http.ResponseWriter, r *http.Request) {
	st := getState(r.Context())
	title := s.t(r, "page.account.title")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.render(w, r, accountData{
			layoutData: layoutData{
				Title:        title,
				BodyTemplate: "account",
				User:         st.User,
				HasUsers:     st.HasUsers,
				Error:        s.t(r, "error.badRequest"),
			},
		})
		return
	}

	newPassword := r.FormValue("newPassword")
	if err := storage.UpdateUserPassword(s.db, st.User.ID, newPassword); err != nil {
		s.render(w, r, accountData{
			layoutData: layoutData{
				Title:        title,
				BodyTemplate: "account",
				User:         st.User,
				HasUsers:     st.HasUsers,
				Error:        err.Error(),
			},
		})
		return
	}
	http.Redirect(w, r, "/account?ok=1", http.StatusFound)
}

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

func (s *server) configVersions(w http.ResponseWriter, r *http.Request) {
	st := getState(r.Context())
	title := s.t(r, "page.versions.title")
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	versions, err := s.config.ListVersions(100)
	if err != nil {
		s.render(w, r, versionsData{
			layoutData: layoutData{
				Title:        title,
				BodyTemplate: "versions",
				User:         st.User,
				HasUsers:     st.HasUsers,
				Error:        err.Error(),
			},
		})
		return
	}

	notice := ""
	if r.URL.Query().Get("ok") != "" {
		notice = s.t(r, "common.applied")
	}
	s.render(w, r, versionsData{
		layoutData: layoutData{
			Title:        title,
			BodyTemplate: "versions",
			User:         st.User,
			HasUsers:     st.HasUsers,
			Notice:       notice,
		},
		Versions: versions,
	})
}

func (s *server) configVersionsSub(w http.ResponseWriter, r *http.Request) {
	st := getState(r.Context())
	title := s.t(r, "page.versions.title")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// /config/versions/{id}/restore
	path := strings.TrimPrefix(r.URL.Path, "/config/versions/")
	if !strings.HasSuffix(path, "/restore") {
		http.NotFound(w, r)
		return
	}
	idRaw := strings.TrimSuffix(path, "/restore")
	idRaw = strings.Trim(idRaw, "/")
	versionID, err := strconv.ParseInt(idRaw, 10, 64)
	if err != nil || versionID <= 0 {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	userID := st.User.ID
	if err := s.config.RestoreVersion(versionID, &userID); err != nil {
		versions, _ := s.config.ListVersions(100)
		s.render(w, r, versionsData{
			layoutData: layoutData{
				Title:        title,
				BodyTemplate: "versions",
				User:         st.User,
				HasUsers:     st.HasUsers,
				Error:        err.Error(),
			},
			Versions: versions,
		})
		return
	}

	http.Redirect(w, r, "/config/versions?ok=1", http.StatusFound)
}

func (s *server) configExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	encrypted, err := s.config.GetEncryptedConfig()
	if err != nil {
		http.Error(w, "Bad gateway", http.StatusBadGateway)
		return
	}

	ts := time.Now().UTC().Format("20060102-150405Z")
	filename := fmt.Sprintf("hazuki-config-%s.json", ts)

	w.Header().Set("content-type", "application/json; charset=utf-8")
	w.Header().Set(
		"content-disposition",
		fmt.Sprintf("attachment; filename=%q; filename*=UTF-8''%s", filename, url.PathEscape(filename)),
	)
	enc, _ := json.MarshalIndent(encrypted, "", "  ")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(enc)
}

func (s *server) configImport(w http.ResponseWriter, r *http.Request) {
	st := getState(r.Context())
	title := s.t(r, "page.import.title")
	switch r.Method {
	case http.MethodGet:
		s.render(w, r, importData{
			layoutData: layoutData{
				Title:        title,
				BodyTemplate: "import",
				User:         st.User,
				HasUsers:     st.HasUsers,
			},
		})
		return
	case http.MethodPost:
		// continue
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		s.render(w, r, importData{
			layoutData: layoutData{
				Title:        title,
				BodyTemplate: "import",
				User:         st.User,
				HasUsers:     st.HasUsers,
				Error:        s.t(r, "error.badRequest"),
			},
		})
		return
	}

	raw := r.FormValue("configJson")
	var parsed model.AppConfig
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		s.render(w, r, importData{
			layoutData: layoutData{
				Title:        title,
				BodyTemplate: "import",
				User:         st.User,
				HasUsers:     st.HasUsers,
				Error:        fmt.Sprintf("%s: %s", s.t(r, "error.jsonInvalid"), err.Error()),
			},
			ConfigJSON: raw,
		})
		return
	}
	if err := parsed.Validate(); err != nil {
		s.render(w, r, importData{
			layoutData: layoutData{
				Title:        title,
				BodyTemplate: "import",
				User:         st.User,
				HasUsers:     st.HasUsers,
				Error:        fmt.Sprintf("%s: %s", s.t(r, "error.configInvalid"), err.Error()),
			},
			ConfigJSON: raw,
		})
		return
	}

	userID := st.User.ID
	if err := s.config.Update(storage.UpdateRequest{
		UserID: &userID,
		Note:   "import",
		Updater: func(_ model.AppConfig) (model.AppConfig, error) {
			return parsed, nil
		},
	}); err != nil {
		s.render(w, r, importData{
			layoutData: layoutData{
				Title:        title,
				BodyTemplate: "import",
				User:         st.User,
				HasUsers:     st.HasUsers,
				Error:        s.errText(r, err),
			},
			ConfigJSON: raw,
		})
		return
	}

	http.Redirect(w, r, "/config/versions?ok=1", http.StatusFound)
}

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
			HealthURL: baseURL + "/_hazuki/health",
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
				HealthURL: baseURL + "/_hazuki/health",
				Status:    st,
			})
		}
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
		GitHealthURL:      gitBaseURL + "/_hazuki/health",
		GitStatus:         gitSt,

		CurrentInstanceID:   currentID,
		CurrentInstanceName: currentName,
		Instances:           instances,
	})
}

func (s *server) renderCdnjsForm(w http.ResponseWriter, r *http.Request, st *reqState, cfg model.AppConfig, notice, errMsg, cdnjsPortValue, ghUserPolicyValue, allowedUsersCsv, blockedUsersCsv, redisPortValue, defaultTTLValue, ttlOverridesValue string) {
	if strings.TrimSpace(cdnjsPortValue) == "" {
		cdnjsPortValue = strconv.Itoa(cfg.Ports.Cdnjs)
	}
	if strings.TrimSpace(ghUserPolicyValue) == "" {
		ghUserPolicyValue = strings.TrimSpace(cfg.Cdnjs.GhUserPolicy)
	}
	ghUserPolicyValue = strings.ToLower(strings.TrimSpace(ghUserPolicyValue))
	if ghUserPolicyValue == "" {
		ghUserPolicyValue = "allowlist"
	}
	if strings.TrimSpace(allowedUsersCsv) == "" {
		allowedUsersCsv = strings.Join(cfg.Cdnjs.AllowedGhUsers, ",")
	}
	if strings.TrimSpace(blockedUsersCsv) == "" {
		blockedUsersCsv = strings.Join(cfg.Cdnjs.BlockedGhUsers, ",")
	}
	if strings.TrimSpace(redisPortValue) == "" {
		redisPortValue = strconv.Itoa(cfg.Cdnjs.Redis.Port)
	}
	if strings.TrimSpace(defaultTTLValue) == "" {
		if cfg.Cdnjs.DefaultTTLSeconds > 0 {
			defaultTTLValue = strconv.Itoa(cfg.Cdnjs.DefaultTTLSeconds)
		}
	}
	if strings.TrimSpace(ttlOverridesValue) == "" {
		ttlOverridesValue = formatTTLOverrides(cfg.Cdnjs.CacheTTLSeconds)
	}

	effectiveDefaultTTL, effectiveTTLMap := cdnjsproxy.EffectiveCacheTTLConfig(cfg.Cdnjs)
	type ttlPreview struct {
		DefaultTTLSeconds int            `json:"defaultTTLSeconds"`
		TTLByExt          map[string]int `json:"ttlByExt"`
	}
	ttlPreviewJSON, _ := json.Marshal(ttlPreview{
		DefaultTTLSeconds: effectiveDefaultTTL,
		TTLByExt:          effectiveTTLMap,
	})

	cdnjsBaseURL := baseURLForPort(r, cfg.Ports.Cdnjs)
	redisSt := checkRedisStatus(r.Context(), cfg.Cdnjs.Redis.Host, cfg.Cdnjs.Redis.Port)
	cdnjsSt := func() serviceStatus {
		if cfg.Cdnjs.Disabled {
			return disabledServiceStatus(cfg.Ports.Cdnjs)
		}
		return checkServiceStatus(r.Context(), cfg.Ports.Cdnjs)
	}()

	s.render(w, r, cdnjsData{
		layoutData: layoutData{
			Title:        s.t(r, "page.cdnjs.title"),
			BodyTemplate: "cdnjs",
			User:         st.User,
			HasUsers:     st.HasUsers,
			Notice:       notice,
			Error:        errMsg,
		},
		Cdnjs:             cfg.Cdnjs,
		CdnjsPort:         cfg.Ports.Cdnjs,
		CdnjsPortValue:    cdnjsPortValue,
		GhUserPolicyValue: ghUserPolicyValue,
		AllowedUsersCsv:   allowedUsersCsv,
		BlockedUsersCsv:   blockedUsersCsv,
		RedisPortValue:    redisPortValue,
		DefaultTTLValue:   defaultTTLValue,
		TTLOverridesValue: ttlOverridesValue,
		TTLEffectiveJSON:  template.JS(string(ttlPreviewJSON)),
		CdnjsBaseURL:      cdnjsBaseURL,
		CdnjsHealthURL:    cdnjsBaseURL + "/_hazuki/health",
		RedisStatus:       redisSt,
		CdnjsStatus:       cdnjsSt,
	})
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
		TorcherinoHealthURL: baseURL + "/_hazuki/health",
		TorcherinoStatus:    torcherinoSt,
	})
}

func isSecureRequest(r *http.Request) bool {
	xfProto := r.Header.Get("X-Forwarded-Proto")
	proto := strings.ToLower(strings.TrimSpace(strings.Split(xfProto, ",")[0]))
	return proto == "https"
}

func requestScheme(r *http.Request) string {
	if isSecureRequest(r) || r.TLS != nil {
		return "https"
	}
	return "http"
}

func requestHostName(r *http.Request) string {
	host := strings.TrimSpace(r.Host)
	if host == "" {
		return "127.0.0.1"
	}
	hostName := host
	if h, _, err := net.SplitHostPort(host); err == nil && strings.TrimSpace(h) != "" {
		hostName = h
	}
	hostName = strings.TrimPrefix(hostName, "[")
	hostName = strings.TrimSuffix(hostName, "]")
	if hostName == "" {
		return "127.0.0.1"
	}
	return hostName
}

func baseURLForPort(r *http.Request, port int) string {
	scheme := requestScheme(r)
	hostPort := net.JoinHostPort(requestHostName(r), strconv.Itoa(port))
	return scheme + "://" + hostPort
}

func checkRedisStatus(ctx context.Context, host string, port int) redisStatus {
	host = strings.TrimSpace(host)
	if host == "" || port <= 0 || port > 65535 {
		return redisStatus{Status: "disabled"}
	}

	addr := ""
	if h, p, err := net.SplitHostPort(host); err == nil && strings.TrimSpace(h) != "" && strings.TrimSpace(p) != "" {
		addr = net.JoinHostPort(h, p)
	} else {
		addr = net.JoinHostPort(host, strconv.Itoa(port))
	}

	client := redis.NewClient(&redis.Options{
		Addr:         addr,
		MaxRetries:   0,
		PoolSize:     1,
		DialTimeout:  200 * time.Millisecond,
		ReadTimeout:  200 * time.Millisecond,
		WriteTimeout: 200 * time.Millisecond,
	})
	defer func() { _ = client.Close() }()

	pingCtx, cancel := context.WithTimeout(ctx, 350*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := client.Ping(pingCtx).Err()
	latency := time.Since(start)

	if err != nil {
		return redisStatus{
			Addr:      addr,
			Status:    "error",
			LatencyMS: latency.Milliseconds(),
			Error:     err.Error(),
		}
	}

	st := redisStatus{
		Addr:      addr,
		Status:    "ok",
		LatencyMS: latency.Milliseconds(),
	}

	infoCtx, cancel := context.WithTimeout(ctx, 450*time.Millisecond)
	defer cancel()
	infoStr, err := client.Info(infoCtx, "server", "clients", "memory").Result()
	if err == nil && strings.TrimSpace(infoStr) != "" {
		for _, line := range strings.Split(infoStr, "\n") {
			l := strings.TrimSpace(line)
			if l == "" || strings.HasPrefix(l, "#") {
				continue
			}
			key, val, ok := strings.Cut(l, ":")
			if !ok {
				continue
			}
			key = strings.TrimSpace(key)
			val = strings.TrimSpace(val)
			switch key {
			case "redis_version":
				st.ServerVersion = val
			case "uptime_in_seconds":
				if n, err := strconv.ParseInt(val, 10, 64); err == nil {
					st.UptimeSeconds = n
				}
			case "connected_clients":
				if n, err := strconv.ParseInt(val, 10, 64); err == nil {
					st.ConnectedClients = n
				}
			case "used_memory_human":
				st.UsedMemoryHuman = val
			}
		}
	}

	dbSizeCtx, cancel := context.WithTimeout(ctx, 450*time.Millisecond)
	defer cancel()
	if n, err := client.DBSize(dbSizeCtx).Result(); err == nil {
		st.DBSize = n
	}

	return st
}

func disabledServiceStatus(port int) serviceStatus {
	if port <= 0 || port > 65535 {
		return serviceStatus{Status: "disabled"}
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	u := "http://" + addr + "/_hazuki/health"
	return serviceStatus{Addr: addr, URL: u, Status: "disabled"}
}

func checkServiceStatus(ctx context.Context, port int) serviceStatus {
	if port <= 0 || port > 65535 {
		return serviceStatus{Status: "disabled"}
	}

	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	u := "http://" + addr + "/_hazuki/health"

	checkCtx, cancel := context.WithTimeout(ctx, 650*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(checkCtx, http.MethodGet, u, nil)
	if err != nil {
		return serviceStatus{Addr: addr, URL: u, Status: "error", Error: err.Error()}
	}

	client := &http.Client{
		Timeout: 650 * time.Millisecond,
	}

	start := time.Now()
	resp, err := client.Do(req)
	latency := time.Since(start)
	if err != nil {
		return serviceStatus{
			Addr:      addr,
			URL:       u,
			Status:    "error",
			LatencyMS: latency.Milliseconds(),
			Error:     err.Error(),
		}
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		errMsg := fmt.Sprintf("http %d", resp.StatusCode)
		if b := strings.TrimSpace(string(body)); b != "" {
			errMsg += ": " + b
		}
		return serviceStatus{
			Addr:      addr,
			URL:       u,
			Status:    "error",
			LatencyMS: latency.Milliseconds(),
			Error:     errMsg,
		}
	}

	var payload struct {
		OK      bool   `json:"ok"`
		Service string `json:"service"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&payload); err != nil {
		return serviceStatus{
			Addr:      addr,
			URL:       u,
			Status:    "error",
			LatencyMS: latency.Milliseconds(),
			Error:     err.Error(),
		}
	}
	if !payload.OK {
		return serviceStatus{
			Addr:      addr,
			URL:       u,
			Service:   payload.Service,
			Status:    "error",
			LatencyMS: latency.Milliseconds(),
			Error:     "health returned ok=false",
		}
	}

	return serviceStatus{
		Addr:      addr,
		URL:       u,
		Service:   payload.Service,
		Status:    "ok",
		LatencyMS: latency.Milliseconds(),
	}
}

func getSQLiteMainDBPathAndSize(ctx context.Context, db *sql.DB) (path string, sizeBytes int64, err error) {
	rows, err := db.QueryContext(ctx, "PRAGMA database_list;")
	if err != nil {
		return "", 0, err
	}
	defer rows.Close()

	for rows.Next() {
		var seq int
		var name string
		var file string
		if err := rows.Scan(&seq, &name, &file); err != nil {
			return "", 0, err
		}
		if name == "main" {
			path = file
			break
		}
	}
	if err := rows.Err(); err != nil {
		return "", 0, err
	}
	if strings.TrimSpace(path) == "" {
		return "", 0, errors.New("database path is empty")
	}

	st, err := os.Stat(path)
	if err != nil {
		return path, 0, err
	}
	return path, st.Size(), nil
}

func formatBytes(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}

	const unit = 1024
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	suffixes := []string{"KB", "MB", "GB", "TB", "PB", "EB"}
	suffix := "KB"
	if exp >= 0 && exp < len(suffixes) {
		suffix = suffixes[exp]
	}
	return fmt.Sprintf("%.1f %s", float64(n)/float64(div), suffix)
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func setSessionCookie(w http.ResponseWriter, token string, ttlSeconds int, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    token,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   secure,
		Path:     "/",
		MaxAge:   ttlSeconds,
	})
}

func clearSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   secure,
		Path:     "/",
		MaxAge:   -1,
	})
}

func normalizePath(value string) string {
	s := strings.TrimSpace(value)
	if s == "" {
		return "/"
	}
	if !strings.HasPrefix(s, "/") {
		s = "/" + s
	}
	if len(s) > 1 && strings.HasSuffix(s, "/") {
		s = strings.TrimSuffix(s, "/")
	}
	return s
}

func parseCSV(value string) []string {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return []string{}
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		s := strings.TrimSpace(p)
		if s == "" {
			continue
		}
		out = append(out, s)
	}
	return out
}

func parseBool(value string, fallback bool) bool {
	v := strings.TrimSpace(strings.ToLower(value))
	if v == "" {
		return fallback
	}
	switch v {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return fallback
	}
}

func parseStringMapJSON(raw string) (map[string]string, error) {
	if strings.TrimSpace(raw) == "" {
		return map[string]string{}, nil
	}
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return nil, err
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("must be a JSON object")
	}
	out := make(map[string]string, len(obj))
	for k, vv := range obj {
		if strings.TrimSpace(k) == "" {
			continue
		}
		out[k] = fmt.Sprint(vv)
	}
	return out, nil
}

func noteIfEmpty(note, fallback string) string {
	if strings.TrimSpace(note) == "" {
		return fallback
	}
	return note
}

func parsePort(value string, fallback int) (int, error) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 65535 {
		return 0, errI18n("error.portRange")
	}
	return n, nil
}

const maxTTLSeconds = 315360000 // 10 years

func parseTTLSeconds(value string) (int, error) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > maxTTLSeconds {
		return 0, errI18n("error.ttlRange", maxTTLSeconds)
	}
	return n, nil
}

func parseTTLOverrides(raw string) (map[string]int, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}

	// Allow JSON object as an alternative format.
	if strings.HasPrefix(trimmed, "{") {
		var m map[string]int
		if err := json.Unmarshal([]byte(trimmed), &m); err != nil {
			return nil, errI18n("error.ttlOverridesJsonInvalid", err.Error())
		}
		out := make(map[string]int, len(m))
		for k, v := range m {
			ext := normalizeExtKey(k)
			if ext == "" {
				continue
			}
			if v < 1 || v > maxTTLSeconds {
				return nil, errI18n("error.ttlOverridesEntryRange", ext, maxTTLSeconds)
			}
			out[ext] = v
		}
		if len(out) == 0 {
			return nil, nil
		}
		return out, nil
	}

	lines := strings.Split(raw, "\n")
	out := map[string]int{}
	for i, line := range lines {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		if idx := strings.IndexByte(s, '#'); idx != -1 {
			s = strings.TrimSpace(s[:idx])
		}
		if s == "" {
			continue
		}

		sep := strings.IndexAny(s, "=:")
		if sep == -1 {
			return nil, errI18n("error.ttlOverridesLineFormat", i+1)
		}

		ext := normalizeExtKey(strings.TrimSpace(s[:sep]))
		if ext == "" {
			return nil, errI18n("error.ttlOverridesLineEmptyExt", i+1)
		}
		if ext == "default" {
			return nil, errI18n("error.ttlOverridesLineDefaultNotAllowed", i+1)
		}

		ttlRaw := strings.TrimSpace(s[sep+1:])
		n, err := strconv.Atoi(ttlRaw)
		if err != nil || n < 1 || n > maxTTLSeconds {
			return nil, errI18n("error.ttlOverridesLineRange", i+1, maxTTLSeconds)
		}
		out[ext] = n
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func normalizeExtKey(ext string) string {
	s := strings.ToLower(strings.TrimSpace(ext))
	s = strings.TrimPrefix(s, ".")
	return s
}

func formatTTLOverrides(m map[string]int) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		if strings.TrimSpace(k) == "" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(strconv.Itoa(m[k]))
	}
	return b.String()
}

func parseHostMappingJSON(raw string) (map[string]string, error) {
	if strings.TrimSpace(raw) == "" {
		return map[string]string{}, nil
	}
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return nil, err
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("must be a JSON object")
	}
	out := make(map[string]string, len(obj))
	for k, vv := range obj {
		host := strings.TrimSpace(k)
		if host == "" {
			continue
		}
		val, ok := vv.(string)
		if !ok {
			return nil, fmt.Errorf("HOST_MAPPING[%q] must be a string", host)
		}
		target := strings.TrimSpace(val)
		if target == "" {
			continue
		}
		if strings.Contains(host, "://") || strings.Contains(target, "://") {
			return nil, fmt.Errorf("HOST_MAPPING[%q] must be a domain (no http(s)://)", host)
		}
		out[host] = target
	}
	return out, nil
}

func normalizeHeaderName(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func isValidHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i += 1 {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '!' || c == '#' || c == '$' || c == '%' || c == '&' || c == '\'' || c == '*' || c == '+' || c == '-' || c == '.' || c == '^' || c == '_' || c == '`' || c == '|' || c == '~':
		default:
			return false
		}
	}
	return true
}

func parseHeaderNamesCSVStrict(value string) ([]string, error) {
	names := parseCSV(value)
	out := make([]string, 0, len(names))
	seen := make(map[string]struct{}, len(names))
	for _, raw := range names {
		name := normalizeHeaderName(raw)
		if name == "" {
			continue
		}
		if !isValidHeaderName(name) {
			return nil, errI18n("error.workerSecretHeadersInvalid")
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out, nil
}

func mergeSecretHeaderMap(raw string, current map[string]string, clear bool) (map[string]string, error) {
	if clear {
		return map[string]string{}, nil
	}
	currentMap := current
	if currentMap == nil {
		currentMap = map[string]string{}
	}

	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return map[string]string{}, nil
	}

	var v any
	if err := json.Unmarshal([]byte(trimmed), &v); err != nil {
		return nil, errI18n("error.workerSecretHeaderMapJsonInvalid", err.Error())
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, errI18n("error.workerSecretHeaderMapNotObject")
	}

	out := map[string]string{}
	for rawName, rawValue := range obj {
		headerName := normalizeHeaderName(rawName)
		if headerName == "" {
			continue
		}
		if !isValidHeaderName(headerName) {
			return nil, errI18n("error.workerSecretHeaderMapInvalidHeader")
		}

		switch vv := rawValue.(type) {
		case string:
			if vv == "__SET__" {
				if cur, ok := currentMap[headerName]; ok && strings.TrimSpace(cur) != "" {
					out[headerName] = cur
				}
				continue
			}
			val := strings.TrimSpace(vv)
			if val == "" {
				continue
			}
			out[headerName] = val
		case nil:
			continue
		default:
			return nil, errI18n("error.workerSecretHeaderMapValueMustBeString")
		}
	}
	return out, nil
}
