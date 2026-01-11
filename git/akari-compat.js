"use strict";

const fs = require("node:fs");
const path = require("node:path");
const Module = require("node:module");

function parseBoolean(value, fallback) {
  if (value === undefined || value === null || value === "") return fallback;
  const v = value.toString().trim().toLowerCase();
  if (["1", "true", "yes", "y", "on"].includes(v)) return true;
  if (["0", "false", "no", "n", "off"].includes(v)) return false;
  return fallback;
}

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

function resolveAkariDbPath(akariRoot) {
  const fromEnv = (process.env.AKARI_DB_PATH || "").toString().trim();
  if (fromEnv) return path.resolve(fromEnv);
  return path.join(akariRoot, "data", "akari.db");
}

function applyGitEnvFromAkariConfig(config, { preferEnv }) {
  const set = (key, value) => {
    if (preferEnv) {
      const existing = process.env[key];
      if (existing !== undefined && existing !== null && existing.toString().trim() !== "") return;
    }
    process.env[key] = value === undefined || value === null ? "" : value.toString();
  };

  set("GITHUB_TOKEN", config.git.githubToken || "");
  set("GITHUB_AUTH_SCHEME", config.git.githubAuthScheme || "token");

  set("UPSTREAM", config.git.upstream || "raw.githubusercontent.com");
  set(
    "UPSTREAM_MOBILE",
    config.git.upstreamMobile || config.git.upstream || "raw.githubusercontent.com"
  );
  set("UPSTREAM_PATH", config.git.upstreamPath || "/");
  set("UPSTREAM_HTTPS", config.git.https ? "true" : "false");

  set("DISABLE_CACHE", config.git.disableCache ? "true" : "false");
  set("CACHE_CONTROL", (config.git.cacheControl || "").toString());
  set(
    "CACHE_CONTROL_MEDIA",
    (config.git.cacheControlMedia || "public, max-age=43200000").toString()
  );
  set("CACHE_CONTROL_TEXT", (config.git.cacheControlText || "public, max-age=60").toString());

  set("CORS_ORIGIN", (config.git.corsOrigin || "*").toString());
  set("CORS_ALLOW_CREDENTIALS", config.git.corsAllowCredentials ? "true" : "false");
  set("CORS_EXPOSE_HEADERS", (config.git.corsExposeHeaders || "").toString());

  set("BLOCKED_REGION", (config.git.blockedRegions || []).join(","));
  set("BLOCKED_IP_ADDRESS", (config.git.blockedIpAddresses || []).join(","));

  set("REPLACE_DICT", JSON.stringify(config.git.replaceDict || { $upstream: "$custom_domain" }));

  if (config.ports && Number.isFinite(Number(config.ports.git))) {
    set("PORT", String(config.ports.git));
  }
  if (!process.env.HOST || process.env.HOST.toString().trim() === "") {
    process.env.HOST = "0.0.0.0";
  }
}

function loadAkariConfigOrNull() {
  const akariRoot = resolveAkariRoot();
  if (!fs.existsSync(akariRoot)) {
    console.warn(`[akari-compat] akari folder not found: ${akariRoot}`);
    return null;
  }

  const dbPath = resolveAkariDbPath(akariRoot);
  if (!fs.existsSync(dbPath)) {
    console.warn(`[akari-compat] akari db not found: ${dbPath}`);
    return null;
  }

  try {
    const { openDatabase } = require(path.join(akariRoot, "src", "storage", "db"));
    const { migrate } = require(path.join(akariRoot, "src", "storage", "migrate"));
    const { createCryptoContext } = require(path.join(akariRoot, "src", "storage", "crypto"));
    const { ConfigStore } = require(path.join(akariRoot, "src", "storage", "configStore"));

    const db = openDatabase(dbPath);
    migrate(db);

    const cryptoContext = createCryptoContext({ db, masterKey: process.env.AKARI_MASTER_KEY });
    const configStore = new ConfigStore({ db, cryptoContext });
    configStore.initFromEnvironment(process.env);

    return {
      config: configStore.getDecryptedConfig(),
      updatedAt: configStore.getUpdatedAt(),
      dbPath,
    };
  } catch (err) {
    console.error(
      "[akari-compat] failed to read akari config:",
      err && err.message ? err.message : err
    );
    return null;
  }
}

function main() {
  const preferEnv = parseBoolean(process.env.AKARI_COMPAT_PREFER_ENV, false);
  const akariRoot = resolveAkariRoot();
  ensureAkariNodeModulesOnNodePath(akariRoot);
  const loaded = loadAkariConfigOrNull();
  if (loaded) {
    applyGitEnvFromAkariConfig(loaded.config, { preferEnv });
    console.log(
      `[akari-compat] git env loaded from akari db: ${loaded.dbPath}${
        loaded.updatedAt ? ` (updatedAt=${loaded.updatedAt})` : ""
      }`
    );
  } else {
    console.warn("[akari-compat] fallback to local .env / env vars.");
  }

  require("./server.js");
}

main();
