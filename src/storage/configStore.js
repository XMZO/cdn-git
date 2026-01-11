"use strict";

const { EventEmitter } = require("node:events");

const { AppConfigSchema } = require("./schema");

const CONFIG_ROW_ID = 1;
const SECRET_PATHS = [
  "git.githubToken",
  "torcherino.workerSecretKey",
  "torcherino.workerSecretHeaderMap",
];

function nowIso() {
  return new Date().toISOString();
}

function isPlainObject(value) {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function cloneJson(value) {
  return JSON.parse(JSON.stringify(value));
}

function getNested(obj, path) {
  const parts = path.split(".");
  let cur = obj;
  for (const part of parts) {
    if (!isPlainObject(cur) || !(part in cur)) return undefined;
    cur = cur[part];
  }
  return cur;
}

function setNested(obj, path, value) {
  const parts = path.split(".");
  let cur = obj;
  for (let i = 0; i < parts.length - 1; i += 1) {
    const part = parts[i];
    if (!isPlainObject(cur[part])) cur[part] = {};
    cur = cur[part];
  }
  cur[parts[parts.length - 1]] = value;
}

function encryptConfigSecrets({ config, cryptoContext }) {
  const out = cloneJson(config);
  for (const path of SECRET_PATHS) {
    const value = getNested(out, path);
    if (typeof value === "string") {
      if (!value) continue;
      if (value.startsWith("enc:v1:")) continue;
      setNested(out, path, cryptoContext.encryptString(value));
      continue;
    }
    if (isPlainObject(value)) {
      const encrypted = {};
      for (const [k, v] of Object.entries(value)) {
        const raw = (v ?? "").toString();
        if (!raw) {
          encrypted[k] = "";
          continue;
        }
        encrypted[k] = raw.startsWith("enc:v1:") ? raw : cryptoContext.encryptString(raw);
      }
      setNested(out, path, encrypted);
    }
  }
  return out;
}

function decryptConfigSecrets({ config, cryptoContext }) {
  const out = cloneJson(config);
  for (const path of SECRET_PATHS) {
    const value = getNested(out, path);
    if (typeof value === "string") {
      if (!value) continue;
      setNested(out, path, cryptoContext.decryptString(value));
      continue;
    }
    if (isPlainObject(value)) {
      const decrypted = {};
      for (const [k, v] of Object.entries(value)) {
        const raw = (v ?? "").toString();
        decrypted[k] = raw ? cryptoContext.decryptString(raw) : "";
      }
      setNested(out, path, decrypted);
    }
  }
  return out;
}

class ConfigStore extends EventEmitter {
  constructor({ db, cryptoContext }) {
    super();
    this._db = db;
    this._cryptoContext = cryptoContext;

    this._configEncrypted = null;
    this._configDecrypted = null;
    this._updatedAt = null;
  }

  isEncryptionEnabled() {
    return !!(this._cryptoContext && this._cryptoContext.enabled);
  }

  getEncryptedConfig() {
    if (!this._configEncrypted) {
      throw new Error("ConfigStore not initialized");
    }
    return cloneJson(this._configEncrypted);
  }

  initFromEnvironment(env) {
    const existing = this._db
      .prepare("SELECT config_json, updated_at FROM config_current WHERE id = ?")
      .get(CONFIG_ROW_ID);

    if (existing && typeof existing.config_json === "string") {
      const encrypted = JSON.parse(existing.config_json);
      const parsed = AppConfigSchema.parse(encrypted);
      this._configEncrypted = parsed;
      this._configDecrypted = decryptConfigSecrets({
        config: parsed,
        cryptoContext: this._cryptoContext,
      });
      this._updatedAt = existing.updated_at;
      return;
    }

    const seed = AppConfigSchema.parse({
      version: 1,
      ports: {
        admin: 3100,
        torcherino: 3000,
        cdnjs: 3001,
        git: 3002,
      },
      cdnjs: {
        assetUrl: (env.ASSET_URL || "https://cdn.jsdelivr.net").toString(),
        allowedGhUsers: (env.ALLOWED_GH_USERS || "")
          .toString()
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
        defaultGhUser: (env.DEFAULT_GH_USER || "").toString(),
        redis: {
          host: (env.REDIS_HOST || "redis").toString(),
          port: Number.parseInt((env.REDIS_PORT || "6379").toString(), 10) || 6379,
        },
      },
      git: {
        githubToken: (env.GITHUB_TOKEN || "").toString(),
        githubAuthScheme: (env.GITHUB_AUTH_SCHEME || "token").toString(),

        upstream: (env.UPSTREAM || "raw.githubusercontent.com").toString(),
        upstreamMobile: (env.UPSTREAM_MOBILE || env.UPSTREAM || "raw.githubusercontent.com").toString(),
        upstreamPath: (env.UPSTREAM_PATH || "/XMZO/pic/main").toString(),
        https: parseBoolean(env.UPSTREAM_HTTPS, true),

        disableCache: parseBoolean(env.DISABLE_CACHE, false),
        cacheControl: (env.CACHE_CONTROL || "").toString(),
        cacheControlMedia: (env.CACHE_CONTROL_MEDIA || "public, max-age=43200000").toString(),
        cacheControlText: (env.CACHE_CONTROL_TEXT || "public, max-age=60").toString(),

        corsOrigin: (env.CORS_ORIGIN || "*").toString(),
        corsAllowCredentials: parseBoolean(env.CORS_ALLOW_CREDENTIALS, false),
        corsExposeHeaders: (
          env.CORS_EXPOSE_HEADERS ||
          "Accept-Ranges, Content-Length, Content-Range, ETag, Cache-Control, Last-Modified"
        ).toString(),

        blockedRegions: (env.BLOCKED_REGION || "")
          .toString()
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
        blockedIpAddresses:
          env.BLOCKED_IP_ADDRESS !== undefined && env.BLOCKED_IP_ADDRESS !== null
            ? (env.BLOCKED_IP_ADDRESS || "")
                .toString()
                .split(",")
                .map((s) => s.trim())
                .filter(Boolean)
            : ["0.0.0.0", "127.0.0.1"],

        replaceDict: parseJsonObject(env.REPLACE_DICT, { $upstream: "$custom_domain" }),
      },
      torcherino: {
        defaultTarget: (env.DEFAULT_TARGET || "").toString(),
        hostMapping: parseJsonObject(env.HOST_MAPPING, {}),
        workerSecretKey: (env.WORKER_SECRET_KEY || "").toString(),
        workerSecretHeaders: (env.WORKER_SECRET_HEADERS || "")
          .toString()
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
        workerSecretHeaderMap: parseJsonObject(env.WORKER_SECRET_HEADER_MAP, {}),
      },
    });

    const encrypted = encryptConfigSecrets({ config: seed, cryptoContext: this._cryptoContext });

    const insert = this._db.prepare(
      "INSERT INTO config_current (id, config_json, updated_at, updated_by) VALUES (?, ?, ?, ?)"
    );
    const updatedAt = nowIso();
    insert.run(CONFIG_ROW_ID, JSON.stringify(encrypted), updatedAt, null);

    const versionInsert = this._db.prepare(
      "INSERT INTO config_versions (config_json, created_at, created_by, note) VALUES (?, ?, ?, ?)"
    );
    versionInsert.run(JSON.stringify(encrypted), updatedAt, null, "seed");

    this._configEncrypted = encrypted;
    this._configDecrypted = decryptConfigSecrets({
      config: encrypted,
      cryptoContext: this._cryptoContext,
    });
    this._updatedAt = updatedAt;
  }

  getUpdatedAt() {
    return this._updatedAt;
  }

  getDecryptedConfig() {
    if (!this._configDecrypted) {
      throw new Error("ConfigStore not initialized");
    }
    return cloneJson(this._configDecrypted);
  }

  getRedactedConfig() {
    const config = this.getDecryptedConfig();
    config.git.githubToken = config.git.githubToken ? "__SET__" : "";
    config.torcherino.workerSecretKey = config.torcherino.workerSecretKey ? "__SET__" : "";
    config.torcherino.workerSecretHeaderMap = Object.fromEntries(
      Object.entries(config.torcherino.workerSecretHeaderMap || {}).map(([k, v]) => [k, v ? "__SET__" : ""])
    );
    return config;
  }

  listVersions({ limit = 50 } = {}) {
    const rows = this._db
      .prepare(
        "SELECT id, created_at, created_by, note FROM config_versions ORDER BY id DESC LIMIT ?"
      )
      .all(Math.max(1, Math.min(500, Number(limit) || 50)));
    return rows;
  }

  restoreVersion({ versionId, userId }) {
    const row = this._db
      .prepare("SELECT config_json FROM config_versions WHERE id = ?")
      .get(Number(versionId));
    if (!row || typeof row.config_json !== "string") {
      const err = new Error("Config version not found");
      err.statusCode = 404;
      throw err;
    }

    const encrypted = AppConfigSchema.parse(JSON.parse(row.config_json));
    const updatedAt = nowIso();

    const tx = this._db.transaction(() => {
      this._db
        .prepare("UPDATE config_current SET config_json = ?, updated_at = ?, updated_by = ? WHERE id = ?")
        .run(JSON.stringify(encrypted), updatedAt, userId ?? null, CONFIG_ROW_ID);

      this._db
        .prepare(
          "INSERT INTO config_versions (config_json, created_at, created_by, note) VALUES (?, ?, ?, ?)"
        )
        .run(JSON.stringify(encrypted), updatedAt, userId ?? null, `restore:${versionId}`);
    });
    tx();

    this._configEncrypted = encrypted;
    this._configDecrypted = decryptConfigSecrets({
      config: encrypted,
      cryptoContext: this._cryptoContext,
    });
    this._updatedAt = updatedAt;

    this.emit("changed", this.getDecryptedConfig());
  }

  updateConfig({ updater, userId, note, preserveEmptySecrets = true, clearSecrets = [] }) {
    if (typeof updater !== "function") {
      throw new TypeError("updater must be a function");
    }

    const current = this.getDecryptedConfig();
    const nextPlain = AppConfigSchema.parse(updater(current));

    if (preserveEmptySecrets) {
      const clearSet = new Set((clearSecrets || []).map((p) => p.toString()));
      // Keep secrets if updater clears them (common in forms).
      for (const path of SECRET_PATHS) {
        const nextValue = getNested(nextPlain, path);
        if (clearSet.has(path)) continue;
        if (typeof nextValue === "string" && nextValue === "") {
          setNested(nextPlain, path, getNested(current, path) || "");
          continue;
        }
        if (isPlainObject(nextValue) && Object.keys(nextValue).length === 0) {
          const currentValue = getNested(current, path);
          if (isPlainObject(currentValue)) {
            setNested(nextPlain, path, currentValue);
          }
        }
      }
    }

    const nextEncrypted = encryptConfigSecrets({
      config: nextPlain,
      cryptoContext: this._cryptoContext,
    });

    const updatedAt = nowIso();
    const tx = this._db.transaction(() => {
      this._db
        .prepare("UPDATE config_current SET config_json = ?, updated_at = ?, updated_by = ? WHERE id = ?")
        .run(JSON.stringify(nextEncrypted), updatedAt, userId ?? null, CONFIG_ROW_ID);

      this._db
        .prepare(
          "INSERT INTO config_versions (config_json, created_at, created_by, note) VALUES (?, ?, ?, ?)"
        )
        .run(JSON.stringify(nextEncrypted), updatedAt, userId ?? null, note || null);
    });
    tx();

    this._configEncrypted = nextEncrypted;
    this._configDecrypted = decryptConfigSecrets({
      config: nextEncrypted,
      cryptoContext: this._cryptoContext,
    });
    this._updatedAt = updatedAt;

    this.emit("changed", this.getDecryptedConfig());
  }
}

function parseBoolean(value, fallback) {
  if (value === undefined || value === null || value === "") return fallback;
  const v = value.toString().trim().toLowerCase();
  if (["1", "true", "yes", "y", "on"].includes(v)) return true;
  if (["0", "false", "no", "n", "off"].includes(v)) return false;
  return fallback;
}

function parseJsonObject(value, fallback) {
  if (value === undefined || value === null || value === "") return fallback;
  try {
    const parsed = JSON.parse(value.toString());
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return fallback;
    }
    return parsed;
  } catch {
    return fallback;
  }
}

module.exports = { ConfigStore };
