package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"hazuki-go/internal/backup"
	"hazuki-go/internal/metrics"
	"hazuki-go/internal/model"
	"hazuki-go/internal/proxy/cdnjsproxy"
	"hazuki-go/internal/storage"
	"hazuki-go/internal/traffic"
)

type Options struct {
	DB         *sql.DB
	Config     *storage.ConfigStore
	Port       int
	SessionTTL int
	Metrics    *metrics.Registry
	Traffic    *traffic.Persister
}

type server struct {
	db             *sql.DB
	config         *storage.ConfigStore
	port           int
	sessionTTL     int
	startedAt      time.Time
	metrics        *metrics.Registry
	trafficPersist *traffic.Persister
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
		db:             opts.DB,
		config:         opts.Config,
		port:           opts.Port,
		sessionTTL:     opts.SessionTTL,
		startedAt:      time.Now(),
		metrics:        opts.Metrics,
		trafficPersist: opts.Traffic,
	}

	// Best-effort cleanup.
	_ = storage.CleanupExpiredSessions(opts.DB)

	mux := http.NewServeMux()
	mux.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(uiAssetsFS))))
	mux.Handle("/favicon.ico", http.RedirectHandler("/assets/fav.png", http.StatusFound))
	mux.Handle("/fav.png", http.RedirectHandler("/assets/fav.png", http.StatusFound))
	mux.HandleFunc("/_hazuki/health", s.wrapRequireAuth(s.health))
	mux.HandleFunc("/_hazuki/health/", s.wrapRequireAuth(s.healthSub))
	mux.HandleFunc("/_hazuki/stats", s.wrapRequireAuth(s.stats))
	mux.HandleFunc("/setup", s.wrap(s.setup))
	mux.HandleFunc("/login", s.wrap(s.login))
	mux.HandleFunc("/lang", s.wrap(s.setLang))
	mux.HandleFunc("/logout", s.wrapRequireAuth(s.logout))
	mux.HandleFunc("/account", s.wrapRequireAuth(s.account))
	mux.HandleFunc("/account/password", s.wrapRequireAuth(s.accountPassword))
	mux.HandleFunc("/system", s.wrapRequireAuth(s.system))
	mux.HandleFunc("/system/timezone", s.wrapRequireAuth(s.systemTimeZone))
	mux.HandleFunc("/system/master-key", s.wrapRequireAuth(s.systemMasterKey))
	mux.HandleFunc("/system/master-key/verify", s.wrapRequireAuth(s.systemMasterKeyVerify))
	mux.HandleFunc("/system/redis-cache", s.wrapRequireAuth(s.redisCache))
	mux.HandleFunc("/system/redis-cache/clear", s.wrapRequireAuth(s.redisCacheClear))
	mux.HandleFunc("/system/redis-cache/delete", s.wrapRequireAuth(s.redisCacheDelete))
	mux.HandleFunc("/traffic", s.wrapRequireAuth(s.traffic))
	mux.HandleFunc("/traffic/retention", s.wrapRequireAuth(s.trafficRetention))
	mux.HandleFunc("/traffic/cleanup", s.wrapRequireAuth(s.trafficCleanup))
	mux.HandleFunc("/traffic/clear", s.wrapRequireAuth(s.trafficClear))
	mux.HandleFunc("/wizard", s.wrapRequireAuth(s.wizard))
	mux.HandleFunc("/config/git", s.wrapRequireAuth(s.configGit))
	mux.HandleFunc("/config/cdnjs", s.wrapRequireAuth(s.configCdnjs))
	mux.HandleFunc("/config/torcherino", s.wrapRequireAuth(s.configTorcherino))
	mux.HandleFunc("/config/sakuya/oplist", s.wrapRequireAuth(s.configSakuyaOplist))
	// Backward-compatible alias: OneDrive page removed, keep old URL redirecting.
	mux.HandleFunc("/config/sakuya/onedrive", s.wrapRequireAuth(s.configSakuyaOneDrive))
	mux.HandleFunc("/config/versions", s.wrapRequireAuth(s.configVersions))
	mux.HandleFunc("/config/versions/", s.wrapRequireAuth(s.configVersionsSub))
	mux.HandleFunc("/config/export", s.wrapRequireAuth(s.configExport))
	mux.HandleFunc("/config/import", s.wrapRequireAuth(s.configImport))
	mux.HandleFunc("/_hazuki/traffic/series", s.wrapRequireAuth(s.trafficSeries))
	mux.HandleFunc("/", s.wrapRequireAuth(s.dashboard))

	return mux, nil
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
	st := getState(r.Context())
	title := s.t(r, "page.export.title")

	masterKey := strings.TrimSpace(os.Getenv("HAZUKI_MASTER_KEY"))
	masterKeyIsSet := masterKey != ""

	switch r.Method {
	case http.MethodGet:
		s.render(w, r, exportData{
			layoutData: layoutData{
				Title:        title,
				BodyTemplate: "export",
				User:         st.User,
				HasUsers:     st.HasUsers,
			},
			MasterKeyIsSet: masterKeyIsSet,
		})
		return
	case http.MethodPost:
		// continue
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		s.render(w, r, exportData{
			layoutData: layoutData{
				Title:        title,
				BodyTemplate: "export",
				User:         st.User,
				HasUsers:     st.HasUsers,
				Error:        s.t(r, "error.badRequest"),
			},
			MasterKeyIsSet: masterKeyIsSet,
		})
		return
	}

	keyModeRaw := strings.ToLower(strings.TrimSpace(r.FormValue("keyMode")))
	keyMode := backup.KeyMode(keyModeRaw)
	secret := ""

	switch keyMode {
	case backup.KeyModeMaster:
		if !masterKeyIsSet {
			s.render(w, r, exportData{
				layoutData: layoutData{
					Title:        title,
					BodyTemplate: "export",
					User:         st.User,
					HasUsers:     st.HasUsers,
					Error:        s.t(r, "error.exportMasterKeyMissing"),
				},
				MasterKeyIsSet: masterKeyIsSet,
			})
			return
		}
		secret = masterKey
	case backup.KeyModePassword:
		pass := strings.TrimSpace(r.FormValue("password"))
		pass2 := strings.TrimSpace(r.FormValue("password2"))
		if pass == "" {
			s.render(w, r, exportData{
				layoutData: layoutData{
					Title:        title,
					BodyTemplate: "export",
					User:         st.User,
					HasUsers:     st.HasUsers,
					Error:        s.t(r, "error.exportPasswordRequired"),
				},
				MasterKeyIsSet: masterKeyIsSet,
			})
			return
		}
		if pass != pass2 {
			s.render(w, r, exportData{
				layoutData: layoutData{
					Title:        title,
					BodyTemplate: "export",
					User:         st.User,
					HasUsers:     st.HasUsers,
					Error:        s.t(r, "error.exportPasswordMismatch"),
				},
				MasterKeyIsSet: masterKeyIsSet,
			})
			return
		}
		secret = pass
	default:
		s.render(w, r, exportData{
			layoutData: layoutData{
				Title:        title,
				BodyTemplate: "export",
				User:         st.User,
				HasUsers:     st.HasUsers,
				Error:        s.t(r, "error.exportKeyModeInvalid"),
			},
			MasterKeyIsSet: masterKeyIsSet,
		})
		return
	}

	ts := time.Now().UTC().Format("20060102-150405Z")
	filename := fmt.Sprintf("hazuki-backup-%s.hzdb", ts)

	w.Header().Set("content-type", "application/octet-stream")
	w.Header().Set("cache-control", "no-store")
	w.Header().Set("x-content-type-options", "nosniff")
	w.Header().Set(
		"content-disposition",
		fmt.Sprintf("attachment; filename=%q; filename*=UTF-8''%s", filename, url.PathEscape(filename)),
	)

	if err := backup.Export(r.Context(), s.db, w, backup.ExportOptions{
		KeyMode:   keyMode,
		Secret:    secret,
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		ChunkSize: 64 << 10,
	}); err != nil {
		// At this point we may have already started writing the response body.
		log.Printf("admin: backup export failed: %v", err)
	}
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

	const maxUploadBytes = 512 << 20 // 512MB
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)

	mr, err := r.MultipartReader()
	if err != nil {
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

	password := ""

	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
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

		switch strings.TrimSpace(part.FormName()) {
		case "password":
			raw, _ := io.ReadAll(io.LimitReader(part, 64<<10))
			password = strings.TrimSpace(string(raw))
			_ = part.Close()
		case "backupFile":
			masterKey := strings.TrimSpace(os.Getenv("HAZUKI_MASTER_KEY"))
			if _, err := backup.Import(r.Context(), s.db, part, backup.ImportOptions{
				Password:  password,
				MasterKey: masterKey,
			}); err != nil {
				_ = part.Close()
				s.render(w, r, importData{
					layoutData: layoutData{
						Title:        title,
						BodyTemplate: "import",
						User:         st.User,
						HasUsers:     st.HasUsers,
						Error:        s.errText(r, err),
					},
				})
				return
			}
			_ = part.Close()

			nextCrypto, err := storage.NewCryptoContext(s.db, masterKey)
			if err != nil {
				s.render(w, r, importData{
					layoutData: layoutData{
						Title:        title,
						BodyTemplate: "import",
						User:         st.User,
						HasUsers:     st.HasUsers,
						Error:        s.errText(r, err),
					},
				})
				return
			}
			if err := s.config.ReloadFromDB(nextCrypto); err != nil {
				s.render(w, r, importData{
					layoutData: layoutData{
						Title:        title,
						BodyTemplate: "import",
						User:         st.User,
						HasUsers:     st.HasUsers,
						Error:        s.errText(r, err),
					},
				})
				return
			}
			if s.trafficPersist != nil {
				_ = s.trafficPersist.Init(r.Context())
				s.trafficPersist.ResetBaseline()
			}

			http.Redirect(w, r, "/config/versions?ok=1", http.StatusFound)
			return
		default:
			_ = part.Close()
		}
	}

	s.render(w, r, importData{
		layoutData: layoutData{
			Title:        title,
			BodyTemplate: "import",
			User:         st.User,
			HasUsers:     st.HasUsers,
			Error:        s.t(r, "error.badRequest"),
		},
	})
}

func sqliteQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func hasSQLiteTable(ctx context.Context, db *sql.DB, name string) (bool, error) {
	if db == nil {
		return false, errors.New("db is nil")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return false, errors.New("table name is empty")
	}

	var found string
	err := db.QueryRowContext(ctx, "SELECT name FROM sqlite_master WHERE type='table' AND name = ?;", name).Scan(&found)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return false, err
}

func (s *server) importSQLiteBackup(ctx context.Context, backupPath string) error {
	backupPath = strings.TrimSpace(backupPath)
	if backupPath == "" {
		return errI18n("error.importDbInvalid")
	}

	backupDB, err := storage.OpenDB(backupPath)
	if err != nil {
		return errI18n("error.importDbInvalid")
	}
	defer func() { _ = backupDB.Close() }()

	required := []string{"meta", "users", "sessions", "config_current", "config_versions"}
	for _, tbl := range required {
		ok, err := hasSQLiteTable(ctx, backupDB, tbl)
		if err != nil {
			return err
		}
		if !ok {
			return errI18n("error.importDbInvalid")
		}
	}

	var usersCount int64
	if err := backupDB.QueryRowContext(ctx, "SELECT COUNT(*) FROM users;").Scan(&usersCount); err != nil {
		return err
	}
	if usersCount <= 0 {
		return errI18n("error.importDbNoUsers")
	}

	var currentCount int64
	if err := backupDB.QueryRowContext(ctx, "SELECT COUNT(*) FROM config_current WHERE id = 1;").Scan(&currentCount); err != nil {
		return err
	}
	if currentCount != 1 {
		return errI18n("error.importDbInvalid")
	}

	// Pre-verify: ensure the backup can be loaded and decrypted with the current master key,
	// so we don't replace the running DB with an unusable config.
	{
		masterKey := os.Getenv("HAZUKI_MASTER_KEY")
		backupCrypto, err := storage.NewCryptoContext(backupDB, masterKey)
		if err != nil {
			return err
		}
		tmpStore := storage.NewConfigStore(backupDB, backupCrypto)
		if err := tmpStore.InitFromEnvironment(func(string) string { return "" }, func(string) (string, bool) { return "", false }); err != nil {
			return err
		}
	}

	hasTrafficTotals, err := hasSQLiteTable(ctx, backupDB, "traffic_totals")
	if err != nil {
		return err
	}
	hasTrafficBuckets, err := hasSQLiteTable(ctx, backupDB, "traffic_buckets")
	if err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	// Delete in dependency-safe order.
	deleteOrder := []string{
		"sessions",
		"config_versions",
		"config_current",
		"traffic_buckets",
		"traffic_totals",
		"users",
		"meta",
	}
	for _, tbl := range deleteOrder {
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+tbl+";"); err != nil {
			return err
		}
	}

	// meta
	{
		rows, err := backupDB.QueryContext(ctx, "SELECT key, value FROM meta;")
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()

		stmt, err := tx.PrepareContext(ctx, "INSERT INTO meta (key, value) VALUES (?, ?);")
		if err != nil {
			return err
		}
		defer func() { _ = stmt.Close() }()

		for rows.Next() {
			var key, value string
			if err := rows.Scan(&key, &value); err != nil {
				return err
			}
			if _, err := stmt.ExecContext(ctx, key, value); err != nil {
				return err
			}
		}
		if err := rows.Err(); err != nil {
			return err
		}
	}

	// users
	{
		rows, err := backupDB.QueryContext(ctx, "SELECT id, username, password_hash, created_at, updated_at FROM users;")
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()

		stmt, err := tx.PrepareContext(ctx, "INSERT INTO users (id, username, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?);")
		if err != nil {
			return err
		}
		defer func() { _ = stmt.Close() }()

		for rows.Next() {
			var id int64
			var username, passwordHash, createdAt, updatedAt string
			if err := rows.Scan(&id, &username, &passwordHash, &createdAt, &updatedAt); err != nil {
				return err
			}
			if _, err := stmt.ExecContext(ctx, id, username, passwordHash, createdAt, updatedAt); err != nil {
				return err
			}
		}
		if err := rows.Err(); err != nil {
			return err
		}
	}

	// config_current
	{
		rows, err := backupDB.QueryContext(ctx, "SELECT id, config_json, updated_at, updated_by FROM config_current;")
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()

		stmt, err := tx.PrepareContext(ctx, "INSERT INTO config_current (id, config_json, updated_at, updated_by) VALUES (?, ?, ?, ?);")
		if err != nil {
			return err
		}
		defer func() { _ = stmt.Close() }()

		for rows.Next() {
			var id int64
			var configJSON string
			var updatedAt string
			var updatedBy sql.NullInt64
			if err := rows.Scan(&id, &configJSON, &updatedAt, &updatedBy); err != nil {
				return err
			}
			if _, err := stmt.ExecContext(ctx, id, configJSON, updatedAt, updatedBy); err != nil {
				return err
			}
		}
		if err := rows.Err(); err != nil {
			return err
		}
	}

	// config_versions
	{
		rows, err := backupDB.QueryContext(ctx, "SELECT id, config_json, created_at, created_by, note FROM config_versions;")
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()

		stmt, err := tx.PrepareContext(ctx, "INSERT INTO config_versions (id, config_json, created_at, created_by, note) VALUES (?, ?, ?, ?, ?);")
		if err != nil {
			return err
		}
		defer func() { _ = stmt.Close() }()

		for rows.Next() {
			var id int64
			var configJSON, createdAt string
			var createdBy sql.NullInt64
			var note sql.NullString
			if err := rows.Scan(&id, &configJSON, &createdAt, &createdBy, &note); err != nil {
				return err
			}
			if _, err := stmt.ExecContext(ctx, id, configJSON, createdAt, createdBy, note); err != nil {
				return err
			}
		}
		if err := rows.Err(); err != nil {
			return err
		}
	}

	// sessions
	{
		rows, err := backupDB.QueryContext(ctx, "SELECT token_hash, user_id, created_at, expires_at FROM sessions;")
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()

		stmt, err := tx.PrepareContext(ctx, "INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?);")
		if err != nil {
			return err
		}
		defer func() { _ = stmt.Close() }()

		for rows.Next() {
			var tokenHash string
			var userID int64
			var createdAt, expiresAt string
			if err := rows.Scan(&tokenHash, &userID, &createdAt, &expiresAt); err != nil {
				return err
			}
			if _, err := stmt.ExecContext(ctx, tokenHash, userID, createdAt, expiresAt); err != nil {
				return err
			}
		}
		if err := rows.Err(); err != nil {
			return err
		}
	}

	if hasTrafficTotals {
		rows, err := backupDB.QueryContext(ctx, "SELECT service, bytes_in, bytes_out, requests, updated_at FROM traffic_totals;")
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()

		stmt, err := tx.PrepareContext(ctx, "INSERT INTO traffic_totals (service, bytes_in, bytes_out, requests, updated_at) VALUES (?, ?, ?, ?, ?);")
		if err != nil {
			return err
		}
		defer func() { _ = stmt.Close() }()

		for rows.Next() {
			var service string
			var bytesIn, bytesOut, requests int64
			var updatedAt string
			if err := rows.Scan(&service, &bytesIn, &bytesOut, &requests, &updatedAt); err != nil {
				return err
			}
			if _, err := stmt.ExecContext(ctx, service, bytesIn, bytesOut, requests, updatedAt); err != nil {
				return err
			}
		}
		if err := rows.Err(); err != nil {
			return err
		}
	}

	if hasTrafficBuckets {
		rows, err := backupDB.QueryContext(ctx, "SELECT kind, start_ts, service, bytes_in, bytes_out, requests, updated_at FROM traffic_buckets;")
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()

		stmt, err := tx.PrepareContext(ctx, "INSERT INTO traffic_buckets (kind, start_ts, service, bytes_in, bytes_out, requests, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?);")
		if err != nil {
			return err
		}
		defer func() { _ = stmt.Close() }()

		for rows.Next() {
			var kind, service, updatedAt string
			var startTS int64
			var bytesIn, bytesOut, requests int64
			if err := rows.Scan(&kind, &startTS, &service, &bytesIn, &bytesOut, &requests, &updatedAt); err != nil {
				return err
			}
			if _, err := stmt.ExecContext(ctx, kind, startTS, service, bytesIn, bytesOut, requests, updatedAt); err != nil {
				return err
			}
		}
		if err := rows.Err(); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	masterKey := os.Getenv("HAZUKI_MASTER_KEY")
	nextCrypto, err := storage.NewCryptoContext(s.db, masterKey)
	if err != nil {
		return err
	}
	if err := s.config.ReloadFromDB(nextCrypto); err != nil {
		return err
	}
	if s.trafficPersist != nil {
		_ = s.trafficPersist.Init(ctx)
		s.trafficPersist.ResetBaseline()
	}
	return nil
}

func normalizeImportedSecrets(cfg model.AppConfig, backupKdfSaltB64 string, allowClear bool, db *sql.DB) (model.AppConfig, []string, error) {
	out := cfg

	masterKey := os.Getenv("HAZUKI_MASTER_KEY")
	curCrypto, err := storage.NewCryptoContext(db, masterKey)
	if err != nil {
		return model.AppConfig{}, nil, err
	}

	var backupCrypto *storage.CryptoContext
	if strings.TrimSpace(backupKdfSaltB64) != "" {
		backupCrypto, err = storage.NewCryptoContextFromSalt(masterKey, backupKdfSaltB64)
		if err != nil {
			return model.AppConfig{}, nil, err
		}
	}

	cleared := make([]string, 0)
	failed := make([]string, 0)

	decryptOrNormalizeSecret := func(path string, v string) (string, bool, error) {
		raw := strings.TrimSpace(v)
		if raw == "" {
			return "", false, nil
		}
		if raw == "__SET__" {
			return "", false, nil
		}
		if !strings.HasPrefix(raw, "enc:v1:") {
			return raw, false, nil
		}

		dec, err := curCrypto.DecryptString(raw)
		if err == nil {
			return dec, false, nil
		}

		if backupCrypto != nil {
			dec2, err2 := backupCrypto.DecryptString(raw)
			if err2 == nil {
				return dec2, false, nil
			}
			err = err2
		}

		if allowClear {
			return "", true, nil
		}
		return "", false, err
	}

	handle := func(path string, p *string) {
		if p == nil {
			return
		}
		next, didClear, err := decryptOrNormalizeSecret(path, *p)
		if err != nil {
			failed = append(failed, path)
			return
		}
		*p = next
		if didClear {
			cleared = append(cleared, path)
		}
	}

	handle("git.githubToken", &out.Git.GithubToken)
	for i := range out.GitInstances {
		id := strings.TrimSpace(out.GitInstances[i].ID)
		path := fmt.Sprintf("gitInstances.%s.git.githubToken", id)
		handle(path, &out.GitInstances[i].Git.GithubToken)
	}
	handle("torcherino.workerSecretKey", &out.Torcherino.WorkerSecretKey)

	if out.Torcherino.WorkerSecretHeaderMap != nil {
		keys := make([]string, 0, len(out.Torcherino.WorkerSecretHeaderMap))
		for k := range out.Torcherino.WorkerSecretHeaderMap {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := out.Torcherino.WorkerSecretHeaderMap[k]
			path := fmt.Sprintf("torcherino.workerSecretHeaderMap.%s", k)
			next, didClear, err := decryptOrNormalizeSecret(path, v)
			if err != nil {
				failed = append(failed, path)
				continue
			}
			out.Torcherino.WorkerSecretHeaderMap[k] = next
			if didClear {
				cleared = append(cleared, path)
			}
		}
	}

	if len(failed) > 0 {
		return model.AppConfig{}, nil, errI18n("error.importSecretsDecryptFailed", strings.Join(failed, ", "))
	}
	return out, cleared, nil
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
		CdnjsHealthURL:    "/_hazuki/health/cdnjs",
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
		TorcherinoHealthURL: "/_hazuki/health/torcherino",
		TorcherinoStatus:    torcherinoSt,
	})
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

func isSecureRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
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
	infoStr, err := client.Info(infoCtx, "server", "clients", "memory", "stats").Result()
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
			case "keyspace_hits":
				if n, err := strconv.ParseInt(val, 10, 64); err == nil {
					st.KeyspaceHits = n
				}
			case "keyspace_misses":
				if n, err := strconv.ParseInt(val, 10, 64); err == nil {
					st.KeyspaceMisses = n
				}
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

func newRedisAdminClient(host string, port int) (*redis.Client, string, bool) {
	host = strings.TrimSpace(host)
	if host == "" || port <= 0 || port > 65535 {
		return nil, "", false
	}

	addr := ""
	if h, p, err := net.SplitHostPort(host); err == nil && strings.TrimSpace(h) != "" && strings.TrimSpace(p) != "" {
		addr = net.JoinHostPort(h, p)
	} else {
		addr = net.JoinHostPort(host, strconv.Itoa(port))
	}

	return redis.NewClient(&redis.Options{
		Addr:         addr,
		MaxRetries:   1,
		PoolSize:     2,
		DialTimeout:  500 * time.Millisecond,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	}), addr, true
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
	return checkServiceStatusWithCookie(ctx, port, "")
}

func checkServiceStatusWithCookie(ctx context.Context, port int, sessionCookie string) serviceStatus {
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

	if strings.TrimSpace(sessionCookie) != "" {
		req.AddCookie(&http.Cookie{Name: cookieName, Value: sessionCookie})
	}

	client := &http.Client{
		Timeout: 650 * time.Millisecond,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
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

func sessionCookieValue(r *http.Request) string {
	if r == nil {
		return ""
	}
	c, err := r.Cookie(cookieName)
	if err != nil {
		return ""
	}
	return c.Value
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

func normalizeAdminTimeZoneSpec(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "auto", true
	}
	sl := strings.ToLower(s)
	switch sl {
	case "auto", "browser", "local":
		return "auto", true
	case "utc", "z":
		return "UTC", true
	}

	if off, ok := storage.ParseTimeZoneOffsetMinutes(s); ok {
		if off == 0 {
			return "UTC", true
		}
		if spec, ok := storage.FormatTimeZoneOffsetMinutes(off); ok {
			return spec, true
		}
	}

	return "", false
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
