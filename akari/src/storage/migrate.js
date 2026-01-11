"use strict";

function getUserVersion(db) {
  return db.pragma("user_version", { simple: true });
}

function setUserVersion(db, version) {
  db.pragma(`user_version = ${Number(version)}`);
}

function migrate(db) {
  const currentVersion = getUserVersion(db);

  if (currentVersion < 1) {
    db.exec(`
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
    `);

    setUserVersion(db, 1);
  }
}

module.exports = { migrate };

