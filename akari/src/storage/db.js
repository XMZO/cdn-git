"use strict";

const fs = require("node:fs");
const path = require("node:path");

const Database = require("better-sqlite3");

function ensureDirectoryExists(dirPath) {
  if (!dirPath) return;
  fs.mkdirSync(dirPath, { recursive: true });
}

function openDatabase(dbPath) {
  const resolvedPath = path.resolve(dbPath);
  ensureDirectoryExists(path.dirname(resolvedPath));

  const db = new Database(resolvedPath);
  db.pragma("foreign_keys = ON");
  db.pragma("journal_mode = WAL");
  db.pragma("synchronous = NORMAL");
  return db;
}

module.exports = { openDatabase };

