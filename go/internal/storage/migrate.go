package storage

import (
	"database/sql"
)

func Migrate(db *sql.DB) error {
	var currentVersion int
	if err := db.QueryRow("PRAGMA user_version;").Scan(&currentVersion); err != nil {
		return err
	}
	if currentVersion < 1 {
		_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS config_current (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  config_json TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by INTEGER,
  FOREIGN KEY(updated_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS config_versions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  config_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  created_by INTEGER,
  note TEXT,
  FOREIGN KEY(created_by) REFERENCES users(id)
);
`)
		if err != nil {
			return err
		}

		if _, err := db.Exec("PRAGMA user_version = 1;"); err != nil {
			return err
		}
		currentVersion = 1
	}

	if currentVersion < 2 {
		_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS traffic_totals (
  service TEXT PRIMARY KEY,
  bytes_in INTEGER NOT NULL DEFAULT 0,
  bytes_out INTEGER NOT NULL DEFAULT 0,
  requests INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS traffic_buckets (
  kind TEXT NOT NULL,
  start_ts INTEGER NOT NULL,
  service TEXT NOT NULL,
  bytes_in INTEGER NOT NULL DEFAULT 0,
  bytes_out INTEGER NOT NULL DEFAULT 0,
  requests INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (kind, start_ts, service)
);
CREATE INDEX IF NOT EXISTS idx_traffic_buckets_kind_start ON traffic_buckets(kind, start_ts);
CREATE INDEX IF NOT EXISTS idx_traffic_buckets_service ON traffic_buckets(service);
`)
		if err != nil {
			return err
		}

		if _, err := db.Exec("PRAGMA user_version = 2;"); err != nil {
			return err
		}
		currentVersion = 2
	}

	return nil
}
