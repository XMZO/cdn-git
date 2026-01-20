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
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"hazuki-go/internal/model"
	"hazuki-go/internal/proxy/cdnjsproxy"
	"hazuki-go/internal/storage"
)

const cookieName = "hazuki_session"

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

	CdnjsRedis redisStatus

	Warnings []string
}

type cdnjsData struct {
	layoutData
	Cdnjs             model.CdnjsConfig
	CdnjsPort         int
	CdnjsPortValue    string
	AllowedUsersCsv   string
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
	TokenIsSet        bool
	AuthScheme        string
	BlockedRegionsCsv string
	BlockedIPsCsv     string
	ReplaceDictJson   string
	GitBaseURL        string
	GitHealthURL      string
	GitStatus         serviceStatus
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

func (s *server) render(w http.ResponseWriter, data any) {
	w.Header().Set("content-type", "text/html; charset=utf-8")
	_ = pageTemplates.ExecuteTemplate(w, "layout", data)
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

	switch r.Method {
	case http.MethodGet:
		s.render(w, layoutData{
			Title:        "初始化管理员",
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
		s.render(w, layoutData{
			Title:        "初始化管理员",
			BodyTemplate: "setup",
			User:         st.User,
			HasUsers:     st.HasUsers,
			Error:        "Bad request",
		})
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	_, err := storage.CreateUser(s.db, username, password)
	if err != nil {
		s.render(w, layoutData{
			Title:        "初始化管理员",
			BodyTemplate: "setup",
			User:         st.User,
			HasUsers:     st.HasUsers,
			Error:        err.Error(),
		})
		return
	}

	user, ok, err := storage.VerifyUserPassword(s.db, username, password)
	if err != nil || !ok {
		s.render(w, layoutData{
			Title:        "初始化管理员",
			BodyTemplate: "setup",
			User:         st.User,
			HasUsers:     st.HasUsers,
			Error:        "Failed to create user",
		})
		return
	}
	token, err := storage.CreateSession(s.db, user.ID, s.sessionTTL)
	if err != nil {
		s.render(w, layoutData{
			Title:        "初始化管理员",
			BodyTemplate: "setup",
			User:         st.User,
			HasUsers:     st.HasUsers,
			Error:        "Failed to create session",
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

	switch r.Method {
	case http.MethodGet:
		s.render(w, layoutData{
			Title:        "登录",
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
		s.render(w, layoutData{
			Title:        "登录",
			BodyTemplate: "login",
			User:         st.User,
			HasUsers:     st.HasUsers,
			Error:        "Bad request",
		})
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")
	user, ok, err := storage.VerifyUserPassword(s.db, username, password)
	if err != nil {
		s.render(w, layoutData{
			Title:        "登录",
			BodyTemplate: "login",
			User:         st.User,
			HasUsers:     st.HasUsers,
			Error:        "Bad request",
		})
		return
	}
	if !ok {
		s.render(w, layoutData{
			Title:        "登录",
			BodyTemplate: "login",
			User:         st.User,
			HasUsers:     st.HasUsers,
			Error:        "登录失败",
		})
		return
	}
	token, err := storage.CreateSession(s.db, user.ID, s.sessionTTL)
	if err != nil {
		s.render(w, layoutData{
			Title:        "登录",
			BodyTemplate: "login",
			User:         st.User,
			HasUsers:     st.HasUsers,
			Error:        "Failed to create session",
		})
		return
	}
	setSessionCookie(w, token, s.sessionTTL, isSecureRequest(r))
	http.Redirect(w, r, "/", http.StatusFound)
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
	cfg, err := s.config.GetDecryptedConfig()
	if err != nil {
		s.render(w, dashboardData{
			layoutData: layoutData{
				Title:        "概览",
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
			warnings = append(warnings, "未设置 HAZUKI_MASTER_KEY：敏感配置将以明文存储在 SQLite 中。")
		}
	}

	if strings.TrimSpace(cfg.Cdnjs.DefaultGhUser) == "" {
		warnings = append(warnings, "cdnjs：DEFAULT_GH_USER 为空，短路径（/xxx）将返回 400。")
	}
	if len(cfg.Cdnjs.AllowedGhUsers) == 0 {
		warnings = append(warnings, "cdnjs：ALLOWED_GH_USERS 为空，/gh/* 将全部拒绝。")
	}
	if redisSt.Status == "error" {
		warnings = append(warnings, "cdnjs：Redis 连接失败，缓存将不可用（或请求会更慢）。")
	}
	if strings.TrimSpace(cfg.Torcherino.DefaultTarget) == "" && len(cfg.Torcherino.HostMapping) == 0 {
		warnings = append(warnings, "torcherino：DEFAULT_TARGET 为空且 HOST_MAPPING 为空，服务将返回 502。")
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

	s.render(w, dashboardData{
		layoutData: layoutData{
			Title:        "概览",
			BodyTemplate: "dashboard",
			User:         st.User,
			HasUsers:     st.HasUsers,
		},
		UpdatedAt: s.config.GetUpdatedAt(),
		Ports:     cfg.Ports,
		AdminURL:  adminURL,

		TorcherinoURL:       torcherinoURL,
		TorcherinoHealthURL: torcherinoURL + "/_hazuki/health",
		TorcherinoStatus:    checkServiceStatus(r.Context(), cfg.Ports.Torcherino),

		CdnjsURL:       cdnjsURL,
		CdnjsHealthURL: cdnjsURL + "/_hazuki/health",
		CdnjsStatus:    checkServiceStatus(r.Context(), cfg.Ports.Cdnjs),

		GitURL:       gitURL,
		GitHealthURL: gitURL + "/_hazuki/health",
		GitStatus:    checkServiceStatus(r.Context(), cfg.Ports.Git),

		CdnjsRedis: redisSt,
		Warnings:   warnings,
	})
}

func (s *server) system(w http.ResponseWriter, r *http.Request) {
	st := getState(r.Context())
	cfg, err := s.config.GetDecryptedConfig()
	if err != nil {
		s.render(w, systemData{
			layoutData: layoutData{
				Title:        "系统",
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

	s.render(w, systemData{
		layoutData: layoutData{
			Title:        "系统",
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

		AdminStatus:      checkServiceStatus(r.Context(), s.port),
		TorcherinoStatus: checkServiceStatus(r.Context(), cfg.Ports.Torcherino),
		CdnjsStatus:      checkServiceStatus(r.Context(), cfg.Ports.Cdnjs),
		GitStatus:        checkServiceStatus(r.Context(), cfg.Ports.Git),

		Redis: checkRedisStatus(r.Context(), cfg.Cdnjs.Redis.Host, cfg.Cdnjs.Redis.Port),
	})
}

func (s *server) configGit(w http.ResponseWriter, r *http.Request) {
	st := getState(r.Context())

	cfg, err := s.config.GetDecryptedConfig()
	if err != nil {
		s.render(w, gitData{
			layoutData: layoutData{
				Title:        "GitHub Raw",
				BodyTemplate: "git",
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
			notice = "已保存"
		}
		s.renderGitForm(w, r, st, cfg, notice, "", strconv.Itoa(cfg.Ports.Git), "")
		return
	case http.MethodPost:
		// continue
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		s.renderGitForm(w, r, st, cfg, "", "Bad request", strconv.Itoa(cfg.Ports.Git), "")
		return
	}

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
	draft.Git.Upstream = upstream
	draft.Git.UpstreamMobile = upstreamMobile
	draft.Git.UpstreamPath = upstreamPath
	draft.Git.HTTPS = httpsEnabled
	draft.Git.GithubAuthScheme = githubAuthScheme
	draft.Git.DisableCache = disableCache
	draft.Git.CacheControl = cacheControl
	draft.Git.CacheControlMedia = cacheControlMedia
	draft.Git.CacheControlText = cacheControlText
	draft.Git.CorsOrigin = corsOrigin
	draft.Git.CorsAllowCredentials = corsAllowCredentials
	draft.Git.CorsExposeHeaders = corsExposeHeaders
	draft.Git.BlockedRegions = blockedRegions
	draft.Git.BlockedIpAddresses = blockedIPs
	if clearGithubToken {
		draft.Git.GithubToken = ""
	}

	gitPortRaw := strings.TrimSpace(r.FormValue("gitPort"))
	gitPort, err := parsePort(gitPortRaw, cfg.Ports.Git)
	if err != nil {
		s.renderGitForm(w, r, st, draft, "", err.Error(), gitPortRaw, r.FormValue("replaceDictJson"))
		return
	}
	draft.Ports.Git = gitPort

	if githubAuthScheme != "token" && githubAuthScheme != "Bearer" {
		s.renderGitForm(w, r, st, draft, "", "GITHUB_AUTH_SCHEME 必须是 token 或 Bearer", gitPortRaw, r.FormValue("replaceDictJson"))
		return
	}

	if corsAllowCredentials && corsOrigin == "*" {
		s.renderGitForm(w, r, st, draft, "", "CORS_ALLOW_CREDENTIALS=true 与 CORS_ORIGIN='*' 不兼容", gitPortRaw, r.FormValue("replaceDictJson"))
		return
	}

	replaceDictRaw := r.FormValue("replaceDictJson")
	replaceDict, err := parseStringMapJSON(replaceDictRaw)
	if err != nil {
		s.renderGitForm(w, r, st, draft, "", fmt.Sprintf("REPLACE_DICT: %v", err), gitPortRaw, replaceDictRaw)
		return
	}
	draft.Git.ReplaceDict = replaceDict

	note := strings.TrimSpace(r.FormValue("note"))
	userID := st.User.ID

	clearSecrets := []string{}
	if clearGithubToken {
		clearSecrets = append(clearSecrets, "git.githubToken")
	}

	err = s.config.Update(storage.UpdateRequest{
		UserID:               &userID,
		Note:                 noteIfEmpty(note, "edit:git"),
		PreserveEmptySecrets: true,
		ClearSecrets:         clearSecrets,
		Updater: func(cur model.AppConfig) (model.AppConfig, error) {
			next := cur
			next.Ports.Git = gitPort
			next.Git.Upstream = upstream
			next.Git.UpstreamMobile = upstreamMobile
			next.Git.UpstreamPath = upstreamPath
			next.Git.HTTPS = httpsEnabled

			next.Git.GithubAuthScheme = githubAuthScheme

			next.Git.DisableCache = disableCache
			next.Git.CacheControl = cacheControl
			next.Git.CacheControlMedia = cacheControlMedia
			next.Git.CacheControlText = cacheControlText

			next.Git.CorsOrigin = corsOrigin
			next.Git.CorsAllowCredentials = corsAllowCredentials
			next.Git.CorsExposeHeaders = corsExposeHeaders

			next.Git.BlockedRegions = blockedRegions
			next.Git.BlockedIpAddresses = blockedIPs
			next.Git.ReplaceDict = replaceDict

			if clearGithubToken {
				next.Git.GithubToken = ""
			} else {
				next.Git.GithubToken = githubToken
			}
			return next, nil
		},
	})
	if err != nil {
		s.renderGitForm(w, r, st, draft, "", err.Error(), gitPortRaw, replaceDictRaw)
		return
	}

	http.Redirect(w, r, "/config/git?ok=1", http.StatusFound)
}

func (s *server) account(w http.ResponseWriter, r *http.Request) {
	st := getState(r.Context())
	notice := ""
	if r.URL.Query().Get("ok") != "" {
		notice = "已保存"
	}
	s.render(w, accountData{
		layoutData: layoutData{
			Title:        "账号",
			BodyTemplate: "account",
			User:         st.User,
			HasUsers:     st.HasUsers,
			Notice:       notice,
		},
	})
}

func (s *server) accountPassword(w http.ResponseWriter, r *http.Request) {
	st := getState(r.Context())
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.render(w, accountData{
			layoutData: layoutData{
				Title:        "账号",
				BodyTemplate: "account",
				User:         st.User,
				HasUsers:     st.HasUsers,
				Error:        "Bad request",
			},
		})
		return
	}

	newPassword := r.FormValue("newPassword")
	if err := storage.UpdateUserPassword(s.db, st.User.ID, newPassword); err != nil {
		s.render(w, accountData{
			layoutData: layoutData{
				Title:        "账号",
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

	cfg, err := s.config.GetDecryptedConfig()
	if err != nil {
		s.render(w, cdnjsData{
			layoutData: layoutData{
				Title:        "jsDelivr 缓存",
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
			notice = "已保存"
		}
		s.renderCdnjsForm(
			w,
			r,
			st,
			cfg,
			notice,
			"",
			strconv.Itoa(cfg.Ports.Cdnjs),
			strings.Join(cfg.Cdnjs.AllowedGhUsers, ","),
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
			"Bad request",
			strconv.Itoa(cfg.Ports.Cdnjs),
			strings.Join(cfg.Cdnjs.AllowedGhUsers, ","),
			strconv.Itoa(cfg.Cdnjs.Redis.Port),
			"",
			"",
		)
		return
	}

	draft := cfg

	assetURL := strings.TrimSpace(r.FormValue("assetUrl"))
	if assetURL == "" {
		assetURL = "https://cdn.jsdelivr.net"
	}
	assetURL = strings.TrimRight(assetURL, "/")
	draft.Cdnjs.AssetURL = assetURL

	defaultUser := strings.TrimSpace(r.FormValue("defaultGhUser"))
	draft.Cdnjs.DefaultGhUser = defaultUser

	allowedUsersRaw := strings.TrimSpace(r.FormValue("allowedGhUsers"))
	allowedUsers := parseCSV(allowedUsersRaw)
	draft.Cdnjs.AllowedGhUsers = allowedUsers

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
		s.renderCdnjsForm(w, r, st, draft, "", err.Error(), cdnjsPortRaw, allowedUsersRaw, r.FormValue("redisPort"), defaultTTLRaw, ttlOverridesRaw)
		return
	}
	draft.Ports.Cdnjs = cdnjsPort

	u, err := url.Parse(assetURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || strings.TrimSpace(u.Host) == "" {
		s.renderCdnjsForm(w, r, st, draft, "", "ASSET_URL 必须是有效的 http(s) URL", cdnjsPortRaw, allowedUsersRaw, r.FormValue("redisPort"), defaultTTLRaw, ttlOverridesRaw)
		return
	}

	redisPortRaw := strings.TrimSpace(r.FormValue("redisPort"))
	redisPort, err := parsePort(redisPortRaw, cfg.Cdnjs.Redis.Port)
	if err != nil {
		s.renderCdnjsForm(w, r, st, draft, "", err.Error(), cdnjsPortRaw, allowedUsersRaw, redisPortRaw, defaultTTLRaw, ttlOverridesRaw)
		return
	}
	draft.Cdnjs.Redis.Port = redisPort

	defaultTTLSeconds, err := parseTTLSeconds(defaultTTLRaw)
	if err != nil {
		s.renderCdnjsForm(w, r, st, draft, "", err.Error(), cdnjsPortRaw, allowedUsersRaw, redisPortRaw, defaultTTLRaw, ttlOverridesRaw)
		return
	}
	draft.Cdnjs.DefaultTTLSeconds = defaultTTLSeconds

	cacheTTLSeconds, err := parseTTLOverrides(ttlOverridesRaw)
	if err != nil {
		s.renderCdnjsForm(w, r, st, draft, "", err.Error(), cdnjsPortRaw, allowedUsersRaw, redisPortRaw, defaultTTLRaw, ttlOverridesRaw)
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
			next.Cdnjs.AssetURL = assetURL
			next.Cdnjs.DefaultGhUser = defaultUser
			next.Cdnjs.AllowedGhUsers = allowedUsers
			next.Cdnjs.Redis.Host = redisHost
			next.Cdnjs.Redis.Port = redisPort
			next.Cdnjs.DefaultTTLSeconds = defaultTTLSeconds
			next.Cdnjs.CacheTTLSeconds = cacheTTLSeconds
			return next, nil
		},
	})
	if err != nil {
		s.renderCdnjsForm(w, r, st, draft, "", err.Error(), cdnjsPortRaw, allowedUsersRaw, redisPortRaw, defaultTTLRaw, ttlOverridesRaw)
		return
	}

	http.Redirect(w, r, "/config/cdnjs?ok=1", http.StatusFound)
}

func (s *server) configTorcherino(w http.ResponseWriter, r *http.Request) {
	st := getState(r.Context())
	cfg, err := s.config.GetDecryptedConfig()
	if err != nil {
		s.render(w, torcherinoData{
			layoutData: layoutData{
				Title:        "Torcherino",
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
			notice = "已保存"
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
		s.renderTorcherinoForm(w, r, st, cfg, "", "Bad request", strconv.Itoa(cfg.Ports.Torcherino), "", "", "", "")
		return
	}

	defaultTarget := strings.TrimSpace(r.FormValue("defaultTarget"))
	hostMappingRaw := r.FormValue("hostMappingJson")
	hostMapping, err := parseHostMappingJSON(hostMappingRaw)
	if err != nil {
		draft := cfg
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
		draft.Torcherino.DefaultTarget = defaultTarget
		draft.Torcherino.HostMapping = hostMapping
		s.renderTorcherinoForm(w, r, st, draft, "", err.Error(), r.FormValue("torcherinoPort"), defaultTarget, hostMappingRaw, r.FormValue("workerSecretHeaders"), r.FormValue("workerSecretHeaderMapJson"))
		return
	}

	clearWorkerSecretHeaderMap := parseBool(r.FormValue("clearWorkerSecretHeaderMap"), false)
	secretHeaderMapRaw := r.FormValue("workerSecretHeaderMapJson")
	mergedHeaderMap, err := mergeSecretHeaderMap(secretHeaderMapRaw, cfg.Torcherino.WorkerSecretHeaderMap, clearWorkerSecretHeaderMap)
	if err != nil {
		draft := cfg
		draft.Torcherino.DefaultTarget = defaultTarget
		draft.Torcherino.HostMapping = hostMapping
		s.renderTorcherinoForm(w, r, st, draft, "", err.Error(), r.FormValue("torcherinoPort"), defaultTarget, hostMappingRaw, r.FormValue("workerSecretHeaders"), secretHeaderMapRaw)
		return
	}

	portRaw := strings.TrimSpace(r.FormValue("torcherinoPort"))
	port, err := parsePort(portRaw, cfg.Ports.Torcherino)
	if err != nil {
		draft := cfg
		draft.Torcherino.DefaultTarget = defaultTarget
		draft.Torcherino.HostMapping = hostMapping
		s.renderTorcherinoForm(w, r, st, draft, "", err.Error(), portRaw, defaultTarget, hostMappingRaw, r.FormValue("workerSecretHeaders"), secretHeaderMapRaw)
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
		draft.Torcherino.DefaultTarget = defaultTarget
		draft.Torcherino.HostMapping = hostMapping
		draft.Torcherino.WorkerSecretHeaders = workerSecretHeaders
		draft.Torcherino.WorkerSecretHeaderMap = mergedHeaderMap
		s.renderTorcherinoForm(w, r, st, draft, "", err.Error(), portRaw, defaultTarget, hostMappingRaw, r.FormValue("workerSecretHeaders"), secretHeaderMapRaw)
		return
	}

	http.Redirect(w, r, "/config/torcherino?ok=1", http.StatusFound)
}

func (s *server) configVersions(w http.ResponseWriter, r *http.Request) {
	st := getState(r.Context())
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	versions, err := s.config.ListVersions(100)
	if err != nil {
		s.render(w, versionsData{
			layoutData: layoutData{
				Title:        "版本 & 备份",
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
		notice = "已操作"
	}
	s.render(w, versionsData{
		layoutData: layoutData{
			Title:        "版本 & 备份",
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
		s.render(w, versionsData{
			layoutData: layoutData{
				Title:        "版本 & 备份",
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

	w.Header().Set("content-type", "application/json; charset=utf-8")
	w.Header().Set("content-disposition", "attachment; filename=\"hazuki-config.json\"")
	enc, _ := json.MarshalIndent(encrypted, "", "  ")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(enc)
}

func (s *server) configImport(w http.ResponseWriter, r *http.Request) {
	st := getState(r.Context())
	switch r.Method {
	case http.MethodGet:
		s.render(w, importData{
			layoutData: layoutData{
				Title:        "导入备份",
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
		s.render(w, importData{
			layoutData: layoutData{
				Title:        "导入备份",
				BodyTemplate: "import",
				User:         st.User,
				HasUsers:     st.HasUsers,
				Error:        "Bad request",
			},
		})
		return
	}

	raw := r.FormValue("configJson")
	var parsed model.AppConfig
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		s.render(w, importData{
			layoutData: layoutData{
				Title:        "导入备份",
				BodyTemplate: "import",
				User:         st.User,
				HasUsers:     st.HasUsers,
				Error:        "JSON 格式错误: " + err.Error(),
			},
			ConfigJSON: raw,
		})
		return
	}
	if err := parsed.Validate(); err != nil {
		s.render(w, importData{
			layoutData: layoutData{
				Title:        "导入备份",
				BodyTemplate: "import",
				User:         st.User,
				HasUsers:     st.HasUsers,
				Error:        "配置不合法: " + err.Error(),
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
		s.render(w, importData{
			layoutData: layoutData{
				Title:        "导入备份",
				BodyTemplate: "import",
				User:         st.User,
				HasUsers:     st.HasUsers,
				Error:        err.Error(),
			},
			ConfigJSON: raw,
		})
		return
	}

	http.Redirect(w, r, "/config/versions?ok=1", http.StatusFound)
}

func (s *server) wizard(w http.ResponseWriter, r *http.Request) {
	st := getState(r.Context())
	current, err := s.config.GetDecryptedConfig()
	if err != nil {
		s.render(w, wizardData{
			layoutData: layoutData{
				Title:        "快速向导",
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
			notice = "已保存"
		}

		hostMappingJSON, _ := json.MarshalIndent(current.Torcherino.HostMapping, "", "  ")
		headerMapJSON, _ := json.MarshalIndent(redacted.Torcherino.WorkerSecretHeaderMap, "", "  ")

		s.render(w, wizardData{
			layoutData: layoutData{
				Title:        "快速向导",
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
		s.render(w, wizardData{
			layoutData: layoutData{
				Title:        "快速向导",
				BodyTemplate: "wizard",
				User:         st.User,
				HasUsers:     st.HasUsers,
				Error:        "Bad request",
			},
		})
		return
	}

	form := wizardData{
		layoutData: layoutData{
			Title:        "快速向导",
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
		s.render(w, form)
		return
	}

	workerSecretHeaders, err := parseHeaderNamesCSVStrict(form.TorcherinoWorkerSecretHeaders)
	if err != nil {
		form.Error = err.Error()
		s.render(w, form)
		return
	}

	mergedHeaderMap, err := mergeSecretHeaderMap(form.TorcherinoWorkerSecretHeaderMap, current.Torcherino.WorkerSecretHeaderMap, clearWorkerSecretHeaderMap)
	if err != nil {
		form.Error = err.Error()
		s.render(w, form)
		return
	}

	defaultTarget := form.TorcherinoDefaultTarget
	hasDefault := strings.TrimSpace(defaultTarget) != ""
	hasMapping := len(hostMapping) > 0
	if !hasDefault && !hasMapping {
		form.Error = "torcherino：请至少填写 DEFAULT_TARGET 或 HOST_MAPPING"
		s.render(w, form)
		return
	}

	cdnjsAllowed := parseCSV(form.CdnjsAllowedGhUsers)
	if strings.TrimSpace(form.CdnjsDefaultGhUser) == "" && len(cdnjsAllowed) == 0 {
		form.Error = "jsDelivr 缓存：请至少填写 DEFAULT_GH_USER 或 ALLOWED_GH_USERS"
		s.render(w, form)
		return
	}

	assetURL := strings.TrimSpace(form.CdnjsAssetURL)
	if assetURL == "" {
		assetURL = current.Cdnjs.AssetURL
	}
	assetURL = strings.TrimRight(assetURL, "/")
	if u, err := url.Parse(assetURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || strings.TrimSpace(u.Host) == "" {
		form.Error = "ASSET_URL 必须是有效的 http(s) URL"
		s.render(w, form)
		return
	}

	redisHost := strings.TrimSpace(form.CdnjsRedisHost)
	if redisHost == "" {
		redisHost = current.Cdnjs.Redis.Host
	}

	redisPort, err := parsePort(form.CdnjsRedisPort, current.Cdnjs.Redis.Port)
	if err != nil {
		form.Error = err.Error()
		s.render(w, form)
		return
	}

	upstreamPath := normalizePath(form.GitUpstreamPath)
	parts := strings.Split(strings.Trim(upstreamPath, "/"), "/")
	if len(parts) < 3 {
		form.Error = "UPSTREAM_PATH 至少需要 3 段：/owner/repo/branch"
		s.render(w, form)
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
			next.Cdnjs.AllowedGhUsers = cdnjsAllowed
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
		form.Error = err.Error()
		s.render(w, form)
		return
	}

	http.Redirect(w, r, "/wizard?ok=1", http.StatusFound)
}

func (s *server) renderGitForm(w http.ResponseWriter, r *http.Request, st *reqState, cfg model.AppConfig, notice, errMsg, gitPortValue, replaceDictRaw string) {
	replaceDictJSON := ""
	if strings.TrimSpace(replaceDictRaw) != "" {
		replaceDictJSON = replaceDictRaw
	} else {
		pretty, _ := json.MarshalIndent(cfg.Git.ReplaceDict, "", "  ")
		replaceDictJSON = string(pretty)
	}

	authScheme := cfg.Git.GithubAuthScheme
	if strings.TrimSpace(authScheme) == "" {
		authScheme = "token"
	}

	gitBaseURL := baseURLForPort(r, cfg.Ports.Git)
	gitSt := checkServiceStatus(r.Context(), cfg.Ports.Git)

	if strings.TrimSpace(gitPortValue) == "" {
		gitPortValue = strconv.Itoa(cfg.Ports.Git)
	}

	s.render(w, gitData{
		layoutData: layoutData{
			Title:        "GitHub Raw",
			BodyTemplate: "git",
			User:         st.User,
			HasUsers:     st.HasUsers,
			Notice:       notice,
			Error:        errMsg,
		},
		Git:               cfg.Git,
		GitPort:           cfg.Ports.Git,
		GitPortValue:      gitPortValue,
		TokenIsSet:        cfg.Git.GithubToken != "",
		AuthScheme:        authScheme,
		BlockedRegionsCsv: strings.Join(cfg.Git.BlockedRegions, ","),
		BlockedIPsCsv:     strings.Join(cfg.Git.BlockedIpAddresses, ","),
		ReplaceDictJson:   replaceDictJSON,
		GitBaseURL:        gitBaseURL,
		GitHealthURL:      gitBaseURL + "/_hazuki/health",
		GitStatus:         gitSt,
	})
}

func (s *server) renderCdnjsForm(w http.ResponseWriter, r *http.Request, st *reqState, cfg model.AppConfig, notice, errMsg, cdnjsPortValue, allowedUsersCsv, redisPortValue, defaultTTLValue, ttlOverridesValue string) {
	if strings.TrimSpace(cdnjsPortValue) == "" {
		cdnjsPortValue = strconv.Itoa(cfg.Ports.Cdnjs)
	}
	if strings.TrimSpace(allowedUsersCsv) == "" {
		allowedUsersCsv = strings.Join(cfg.Cdnjs.AllowedGhUsers, ",")
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
	cdnjsSt := checkServiceStatus(r.Context(), cfg.Ports.Cdnjs)

	s.render(w, cdnjsData{
		layoutData: layoutData{
			Title:        "jsDelivr 缓存",
			BodyTemplate: "cdnjs",
			User:         st.User,
			HasUsers:     st.HasUsers,
			Notice:       notice,
			Error:        errMsg,
		},
		Cdnjs:             cfg.Cdnjs,
		CdnjsPort:         cfg.Ports.Cdnjs,
		CdnjsPortValue:    cdnjsPortValue,
		AllowedUsersCsv:   allowedUsersCsv,
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
	torcherinoSt := checkServiceStatus(r.Context(), cfg.Ports.Torcherino)

	s.render(w, torcherinoData{
		layoutData: layoutData{
			Title:        "Torcherino",
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
		return 0, errors.New("端口必须是 1-65535 的整数")
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
		return 0, fmt.Errorf("TTL 必须是 1-%d 的整数（单位：秒）；留空表示使用内置默认", maxTTLSeconds)
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
			return nil, fmt.Errorf("TTL overrides JSON 格式错误: %w", err)
		}
		out := make(map[string]int, len(m))
		for k, v := range m {
			ext := normalizeExtKey(k)
			if ext == "" {
				continue
			}
			if v < 1 || v > maxTTLSeconds {
				return nil, fmt.Errorf("TTL overrides[%q] 必须是 1-%d 的整数（秒）", ext, maxTTLSeconds)
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
			return nil, fmt.Errorf("TTL overrides 第 %d 行错误：请使用 ext=seconds 格式", i+1)
		}

		ext := normalizeExtKey(strings.TrimSpace(s[:sep]))
		if ext == "" {
			return nil, fmt.Errorf("TTL overrides 第 %d 行错误：后缀为空", i+1)
		}
		if ext == "default" {
			return nil, fmt.Errorf("TTL overrides 第 %d 行错误：请用上方 Default TTL，不要写 default=...", i+1)
		}

		ttlRaw := strings.TrimSpace(s[sep+1:])
		n, err := strconv.Atoi(ttlRaw)
		if err != nil || n < 1 || n > maxTTLSeconds {
			return nil, fmt.Errorf("TTL overrides 第 %d 行错误：TTL 必须是 1-%d 的整数（秒）", i+1, maxTTLSeconds)
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
			return nil, errors.New("WORKER_SECRET_HEADERS：Header 名称不合法")
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
		return nil, fmt.Errorf("WORKER_SECRET_HEADER_MAP：JSON 格式错误: %w", err)
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("WORKER_SECRET_HEADER_MAP：JSON must be an object")
	}

	out := map[string]string{}
	for rawName, rawValue := range obj {
		headerName := normalizeHeaderName(rawName)
		if headerName == "" {
			continue
		}
		if !isValidHeaderName(headerName) {
			return nil, errors.New("WORKER_SECRET_HEADER_MAP：Header 名称不合法")
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
			return nil, errors.New("WORKER_SECRET_HEADER_MAP：value 必须是字符串")
		}
	}
	return out, nil
}
