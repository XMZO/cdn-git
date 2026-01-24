package admin

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"hazuki-go/internal/backup"
	"hazuki-go/internal/model"
	"hazuki-go/internal/storage"
)

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
