"use strict";

const fs = require("node:fs");
const path = require("node:path");
const Module = require("node:module");

function resolveAkariRoot() {
  return path.resolve(__dirname, "..", "akari");
}

function ensureAkariNodeModulesOnNodePath(akariRoot) {
  const akariNodeModules = path.join(akariRoot, "node_modules");
  if (!fs.existsSync(akariNodeModules)) return;

  const existing = (process.env.NODE_PATH || "")
    .toString()
    .split(path.delimiter)
    .map((p) => p.trim())
    .filter(Boolean);

  if (existing.includes(akariNodeModules)) return;
  process.env.NODE_PATH = [akariNodeModules, ...existing].join(path.delimiter);
  Module._initPaths();
}

function maybeLoadAkariDotenv(akariRoot) {
  const envPath = path.join(akariRoot, ".env");
  if (!fs.existsSync(envPath)) return;
  require("dotenv").config({ path: envPath });
}

function resolveAkariDbPath(akariRoot) {
  const fromEnv = (process.env.AKARI_DB_PATH || "").toString().trim();
  if (fromEnv) return path.resolve(fromEnv);
  return path.join(akariRoot, "data", "akari.db");
}

function main() {
  const akariRoot = resolveAkariRoot();
  ensureAkariNodeModulesOnNodePath(akariRoot);
  maybeLoadAkariDotenv(akariRoot);

  const dbPath = resolveAkariDbPath(akariRoot);

  const { openDatabase } = require(path.join(akariRoot, "src", "storage", "db"));
  const { migrate } = require(path.join(akariRoot, "src", "storage", "migrate"));
  const { createCryptoContext } = require(path.join(akariRoot, "src", "storage", "crypto"));
  const { ConfigStore } = require(path.join(akariRoot, "src", "storage", "configStore"));
  const { startGitServer } = require(path.join(akariRoot, "src", "proxies", "git"));

  const db = openDatabase(dbPath);
  migrate(db);

  const cryptoContext = createCryptoContext({ db, masterKey: process.env.AKARI_MASTER_KEY });
  const configStore = new ConfigStore({ db, cryptoContext });
  configStore.initFromEnvironment(process.env);

  startGitServer({ configStore });
  console.log(`[akari-git] using db: ${dbPath}`);
}

main();
