"use strict";

const express = require("express");

const { AppConfigSchema } = require("../storage/schema");
const { countUsers, createUser, ensureBootstrapAdmin, verifyUserPassword, updateUserPassword } = require("../storage/users");
const { cleanupExpiredSessions, createSession, deleteSession, getSessionUser } = require("../storage/sessions");
const {
  renderLayout,
  renderLoginPage,
  renderSetupPage,
  renderDashboard,
  renderAccountPage,
  renderCdnjsForm,
  renderGitForm,
  renderTorcherinoForm,
  renderVersionsPage,
  renderImportPage,
  renderWizardPage,
} = require("./views");

const COOKIE_NAME = "hazuki_session";

function startAdminServer({ db, configStore }) {
  const app = express();
  app.disable("x-powered-by");
  app.use(express.urlencoded({ extended: false, limit: "256kb" }));

  // Best-effort cleanup.
  try {
    cleanupExpiredSessions({ db });
  } catch {
    // ignore
  }

  app.use((req, _res, next) => {
    req.user = null;
    req.hasUsers = countUsers({ db }) > 0;
    const token = readCookie(req.headers.cookie || "", COOKIE_NAME);
    if (!token) return next();
    const user = getSessionUser({ db, token });
    if (!user) return next();
    req.user = user;
    return next();
  });

  app.get("/login", (req, res) => {
    if (!req.hasUsers) return res.redirect("/setup");
    if (req.user) return res.redirect("/");
    const error = req.query.error ? "登录失败" : "";
    res.type("html").send(renderLoginPage({ error }));
  });

  app.post("/login", (req, res) => {
    if (!req.hasUsers) return res.redirect("/setup");
    const username = (req.body.username || "").toString();
    const password = (req.body.password || "").toString();
    const user = verifyUserPassword({ db, username, password });
    if (!user) return res.redirect("/login?error=1");

    const ttlSeconds = Number.parseInt((process.env.HAZUKI_SESSION_TTL_SECONDS || "86400").toString(), 10) || 86400;
    const token = createSession({ db, userId: user.id, ttlSeconds });

    const secure = isSecureRequest(req);
    res.cookie(COOKIE_NAME, token, {
      httpOnly: true,
      sameSite: "strict",
      secure,
      path: "/",
      maxAge: ttlSeconds * 1000,
    });
    res.redirect("/");
  });

  app.get("/setup", (req, res) => {
    if (req.hasUsers) return res.redirect(req.user ? "/" : "/login");
    res.type("html").send(renderSetupPage({ error: "" }));
  });

  app.post("/setup", (req, res) => {
    if (req.hasUsers) return res.status(403).type("text/plain; charset=utf-8").send("Forbidden");

    const username = (req.body.username || "").toString();
    const password = (req.body.password || "").toString();

    try {
      const created = createUser({ db, username, password });
      if (!created) throw new Error("Failed to create user");

      const ttlSeconds =
        Number.parseInt((process.env.HAZUKI_SESSION_TTL_SECONDS || "86400").toString(), 10) || 86400;
      const token = createSession({ db, userId: created.id, ttlSeconds });

      const secure = isSecureRequest(req);
      res.cookie(COOKIE_NAME, token, {
        httpOnly: true,
        sameSite: "strict",
        secure,
        path: "/",
        maxAge: ttlSeconds * 1000,
      });

      res.redirect("/");
    } catch (err) {
      res.status(400).type("html").send(
        renderSetupPage({
          error: err && err.message ? err.message : "Bad request",
        })
      );
    }
  });

  app.post("/logout", requireAuth, (req, res) => {
    const token = readCookie(req.headers.cookie || "", COOKIE_NAME);
    if (token) deleteSession({ db, token });
    res.clearCookie(COOKIE_NAME, { path: "/" });
    res.redirect("/login");
  });

  app.get("/", requireAuth, (req, res) => {
    const config = configStore.getDecryptedConfig();
    const warnings = [];

    if (!configStore.isEncryptionEnabled()) {
      const hasSecret = !!(config.git.githubToken || config.torcherino.workerSecretKey);
      if (hasSecret) {
        warnings.push("未设置 HAZUKI_MASTER_KEY：敏感配置将以明文存储在 SQLite 中。");
      }
    }

    if (!config.cdnjs.defaultGhUser) {
      warnings.push("cdnjs: DEFAULT_GH_USER 为空，短路径（/xxx）将返回 400。");
    }
    if ((config.cdnjs.allowedGhUsers || []).length === 0) {
      warnings.push("cdnjs: ALLOWED_GH_USERS 为空，/gh/* 将全部拒绝。");
    }

    const torcherinoMappingCount = Object.keys(config.torcherino.hostMapping || {}).length;
    if (!config.torcherino.defaultTarget && torcherinoMappingCount === 0) {
      warnings.push("torcherino: DEFAULT_TARGET 为空且 HOST_MAPPING 为空，服务将返回 502。");
    }

    const content = renderDashboard({
      updatedAt: configStore.getUpdatedAt(),
      ports: config.ports,
      warnings,
    });
    res.type("html").send(renderLayout({ title: "概览", user: req.user, content }));
  });

  app.get("/account", requireAuth, (req, res) => {
    const notice = req.query.ok ? "已更新" : "";
    res
      .type("html")
      .send(renderLayout({ title: "账号", user: req.user, content: renderAccountPage(), notice }));
  });

  app.post("/account/password", requireAuth, (req, res) => {
    const newPassword = (req.body.newPassword || "").toString();
    try {
      updateUserPassword({ db, userId: req.user.id, newPassword });
      res.redirect("/account?ok=1");
    } catch (err) {
      res
        .status(400)
        .type("html")
        .send(
          renderLayout({
            title: "账号",
            user: req.user,
            content: renderAccountPage(),
            error: err && err.message ? err.message : "Bad request",
          })
        );
    }
  });

  app.get("/wizard", requireAuth, (req, res) => {
    const config = configStore.getDecryptedConfig();
    const form = buildWizardFormFromConfig(config);
    const tokenIsSet = !!config.git.githubToken;
    const secretIsSet = !!config.torcherino.workerSecretKey;

    res.type("html").send(
      renderLayout({
        title: "快速向导",
        user: req.user,
        content: renderWizardPage({ form, tokenIsSet, secretIsSet }),
        notice: req.query.ok ? "已保存" : "",
      })
    );
  });

  app.post("/wizard", requireAuth, (req, res) => {
    const currentConfig = configStore.getDecryptedConfig();
    const tokenIsSet = !!currentConfig.git.githubToken;
    const secretIsSet = !!currentConfig.torcherino.workerSecretKey;

    const form = buildWizardFormFromBody(req.body || {}, currentConfig);

    try {
      const torcherinoDefaultTarget = (req.body.torcherinoDefaultTarget || "").toString().trim();
      const torcherinoHostMapping = parseJsonObject(req.body.torcherinoHostMappingJson);
      const torcherinoWorkerSecretKey = (req.body.torcherinoWorkerSecretKey || "").toString();
      const torcherinoWorkerSecretHeaders = parseHeaderNamesCsv(req.body.torcherinoWorkerSecretHeaders);
      const torcherinoWorkerSecretHeaderMap = parseJsonObject(req.body.torcherinoWorkerSecretHeaderMapJson);
      const torcherinoClearWorkerSecretKey = parseBoolean(req.body.torcherinoClearWorkerSecretKey, false);
      const torcherinoClearWorkerSecretHeaderMap = parseBoolean(req.body.torcherinoClearWorkerSecretHeaderMap, false);

      const cdnjsDefaultGhUser = (req.body.cdnjsDefaultGhUser || "").toString().trim();
      const cdnjsAllowedGhUsers = parseCsv(req.body.cdnjsAllowedGhUsers);

      const cdnjsAssetUrl = (req.body.cdnjsAssetUrl || "").toString().trim() || currentConfig.cdnjs.assetUrl;
      const cdnjsRedisHost = (req.body.cdnjsRedisHost || "").toString().trim() || currentConfig.cdnjs.redis.host;
      const cdnjsRedisPortRaw = (req.body.cdnjsRedisPort || "").toString().trim();
      const cdnjsRedisPort = cdnjsRedisPortRaw
        ? Number.parseInt(cdnjsRedisPortRaw, 10)
        : Number(currentConfig.cdnjs.redis.port);
      if (!Number.isFinite(cdnjsRedisPort) || cdnjsRedisPort < 1 || cdnjsRedisPort > 65535) {
        throw new Error("REDIS_PORT 必须是 1-65535 的整数");
      }

      const gitUpstreamPath = normalizePath((req.body.gitUpstreamPath || "").toString());
      const gitGithubToken = (req.body.gitGithubToken || "").toString();
      const gitClearGithubToken = parseBoolean(req.body.gitClearGithubToken, false);

      const torcherinoHasDefault = !!torcherinoDefaultTarget;
      const torcherinoHasMapping = torcherinoHostMapping && Object.keys(torcherinoHostMapping).length > 0;
      if (!torcherinoHasDefault && !torcherinoHasMapping) {
        throw new Error("torcherino：请至少填写 DEFAULT_TARGET 或 HOST_MAPPING");
      }

      for (const [k, v] of Object.entries(torcherinoHostMapping || {})) {
        if (!k || typeof k !== "string") throw new Error("HOST_MAPPING：key 必须是字符串");
        if (!v || typeof v !== "string") throw new Error("HOST_MAPPING：value 必须是字符串");
        if (k.includes("://") || v.includes("://")) {
          throw new Error("HOST_MAPPING：请只填写域名（不要带 http(s)://）");
        }
      }

      if (!cdnjsDefaultGhUser && cdnjsAllowedGhUsers.length === 0) {
        throw new Error("jsDelivr 缓存：请至少填写 DEFAULT_GH_USER 或 ALLOWED_GH_USERS");
      }

      const upstreamParts = gitUpstreamPath.split("/").filter(Boolean);
      if (upstreamParts.length < 3) {
        throw new Error("UPSTREAM_PATH 至少需要 3 段：/owner/repo/branch");
      }

      configStore.updateConfig({
        userId: req.user.id,
        note: "wizard",
        clearSecrets: [
          ...(gitClearGithubToken ? ["git.githubToken"] : []),
          ...(torcherinoClearWorkerSecretKey ? ["torcherino.workerSecretKey"] : []),
          ...(torcherinoClearWorkerSecretHeaderMap ? ["torcherino.workerSecretHeaderMap"] : []),
        ],
        updater: (cfg) => {
          const workerSecretHeaderMap = torcherinoClearWorkerSecretHeaderMap
            ? {}
            : mergeSecretHeaderMap({
                input: torcherinoWorkerSecretHeaderMap,
                current: cfg.torcherino.workerSecretHeaderMap,
              });
          return {
            ...cfg,
            torcherino: {
              ...cfg.torcherino,
              defaultTarget: torcherinoDefaultTarget,
              hostMapping: torcherinoHostMapping,
              workerSecretKey: torcherinoClearWorkerSecretKey ? "" : torcherinoWorkerSecretKey || "",
              workerSecretHeaders: torcherinoWorkerSecretHeaders,
              workerSecretHeaderMap,
            },
            cdnjs: {
              ...cfg.cdnjs,
              assetUrl: cdnjsAssetUrl,
              allowedGhUsers: cdnjsAllowedGhUsers,
              defaultGhUser: cdnjsDefaultGhUser,
              redis: {
                host: cdnjsRedisHost,
                port: cdnjsRedisPort,
              },
            },
            git: {
              ...cfg.git,
              upstreamPath: gitUpstreamPath,
              githubToken: gitClearGithubToken ? "" : gitGithubToken || "",
            },
          };
        },
      });

      res.redirect("/wizard?ok=1");
    } catch (err) {
      res.status(400).type("html").send(
        renderLayout({
          title: "快速向导",
          user: req.user,
          content: renderWizardPage({ form, tokenIsSet, secretIsSet }),
          error: err && err.message ? err.message : "Bad request",
        })
      );
    }
  });

  app.get("/config/cdnjs", requireAuth, (req, res) => {
    const config = configStore.getDecryptedConfig();
    res.type("html").send(
      renderLayout({
        title: "jsDelivr 缓存",
        user: req.user,
        content: renderCdnjsForm({ config }),
        notice: req.query.ok ? "已保存" : "",
      })
    );
  });

  app.post("/config/cdnjs", requireAuth, (req, res) => {
    try {
      const assetUrl = (req.body.assetUrl || "").toString().trim();
      const allowedGhUsers = parseCsv(req.body.allowedGhUsers);
      const defaultGhUser = (req.body.defaultGhUser || "").toString().trim();
      const redisHost = (req.body.redisHost || "").toString().trim();
      const redisPort = Number.parseInt((req.body.redisPort || "").toString(), 10);

      configStore.updateConfig({
        userId: req.user.id,
        note: "edit:cdnjs",
        updater: (cfg) => {
          return {
            ...cfg,
            cdnjs: {
              ...cfg.cdnjs,
              assetUrl,
              allowedGhUsers,
              defaultGhUser,
              redis: { host: redisHost, port: redisPort },
            },
          };
        },
      });
      res.redirect("/config/cdnjs?ok=1");
    } catch (err) {
      const config = configStore.getDecryptedConfig();
      res.status(400).type("html").send(
        renderLayout({
          title: "jsDelivr 缓存",
          user: req.user,
          content: renderCdnjsForm({ config }),
          error: err && err.message ? err.message : "Bad request",
        })
      );
    }
  });

  app.get("/config/git", requireAuth, (req, res) => {
    const config = configStore.getDecryptedConfig();
    const tokenIsSet = !!config.git.githubToken;
    res.type("html").send(
      renderLayout({
        title: "GitHub Raw",
        user: req.user,
        content: renderGitForm({ config, tokenIsSet }),
        notice: req.query.ok ? "已保存" : "",
      })
    );
  });

  app.post("/config/git", requireAuth, (req, res) => {
    try {
      const githubToken = (req.body.githubToken || "").toString();
      const clearGithubToken = parseBoolean(req.body.clearGithubToken, false);
      const githubAuthScheme = (req.body.githubAuthScheme || "token").toString();
      const upstream = (req.body.upstream || "").toString().trim();
      const upstreamMobile = (req.body.upstreamMobile || "").toString().trim();
      const upstreamPath = normalizePath((req.body.upstreamPath || "").toString());
      const https = parseBoolean(req.body.https, true);
      const disableCache = parseBoolean(req.body.disableCache, false);

      const cacheControl = (req.body.cacheControl || "").toString();
      const cacheControlMedia = (req.body.cacheControlMedia || "").toString();
      const cacheControlText = (req.body.cacheControlText || "").toString();

      const blockedRegions = parseCsv(req.body.blockedRegions);
      const blockedIpAddresses = parseCsv(req.body.blockedIpAddresses);

      const corsOrigin = (req.body.corsOrigin || "*").toString().trim() || "*";
      const corsAllowCredentials = parseBoolean(req.body.corsAllowCredentials, false);
      const corsExposeHeaders = (req.body.corsExposeHeaders || "").toString();

      if (corsAllowCredentials && corsOrigin === "*") {
        throw new Error("CORS_ALLOW_CREDENTIALS=true 与 CORS_ORIGIN='*' 不兼容");
      }

      const replaceDict = parseJsonObject(req.body.replaceDict);

      configStore.updateConfig({
        userId: req.user.id,
        note: "edit:git",
        clearSecrets: clearGithubToken ? ["git.githubToken"] : [],
        updater: (cfg) => {
          return {
            ...cfg,
            git: {
              ...cfg.git,
              githubToken: clearGithubToken ? "" : githubToken || "",
              githubAuthScheme,
              upstream,
              upstreamMobile,
              upstreamPath,
              https,
              disableCache,
              cacheControl,
              cacheControlMedia,
              cacheControlText,
              blockedRegions,
              blockedIpAddresses,
              corsOrigin,
              corsAllowCredentials,
              corsExposeHeaders,
              replaceDict,
            },
          };
        },
      });
      res.redirect("/config/git?ok=1");
    } catch (err) {
      const config = configStore.getDecryptedConfig();
      const tokenIsSet = !!config.git.githubToken;
      res.status(400).type("html").send(
        renderLayout({
          title: "GitHub Raw",
          user: req.user,
          content: renderGitForm({ config, tokenIsSet }),
          error: err && err.message ? err.message : "Bad request",
        })
      );
    }
  });

  app.get("/config/torcherino", requireAuth, (req, res) => {
    const config = configStore.getDecryptedConfig();
    const secretIsSet = !!config.torcherino.workerSecretKey;
    res.type("html").send(
      renderLayout({
        title: "通用反代",
        user: req.user,
        content: renderTorcherinoForm({ config, secretIsSet }),
        notice: req.query.ok ? "已保存" : "",
      })
    );
  });

  app.post("/config/torcherino", requireAuth, (req, res) => {
    try {
      const defaultTarget = (req.body.defaultTarget || "").toString().trim();
      const hostMapping = parseJsonObject(req.body.hostMapping);
      const workerSecretKey = (req.body.workerSecretKey || "").toString();
      const workerSecretHeaders = parseHeaderNamesCsv(req.body.workerSecretHeaders);
      const workerSecretHeaderMap = parseJsonObject(req.body.workerSecretHeaderMapJson);
      const clearWorkerSecretKey = parseBoolean(req.body.clearWorkerSecretKey, false);
      const clearWorkerSecretHeaderMap = parseBoolean(req.body.clearWorkerSecretHeaderMap, false);

      configStore.updateConfig({
        userId: req.user.id,
        note: "edit:torcherino",
        clearSecrets: [
          ...(clearWorkerSecretKey ? ["torcherino.workerSecretKey"] : []),
          ...(clearWorkerSecretHeaderMap ? ["torcherino.workerSecretHeaderMap"] : []),
        ],
        updater: (cfg) => {
          const nextWorkerSecretHeaderMap = clearWorkerSecretHeaderMap
            ? {}
            : mergeSecretHeaderMap({
                input: workerSecretHeaderMap,
                current: cfg.torcherino.workerSecretHeaderMap,
              });
          return {
            ...cfg,
            torcherino: {
              ...cfg.torcherino,
              defaultTarget,
              hostMapping,
              workerSecretKey: clearWorkerSecretKey ? "" : workerSecretKey || "",
              workerSecretHeaders,
              workerSecretHeaderMap: nextWorkerSecretHeaderMap,
            },
          };
        },
      });
      res.redirect("/config/torcherino?ok=1");
    } catch (err) {
      const config = configStore.getDecryptedConfig();
      const secretIsSet = !!config.torcherino.workerSecretKey;
      res.status(400).type("html").send(
        renderLayout({
          title: "通用反代",
          user: req.user,
          content: renderTorcherinoForm({ config, secretIsSet }),
          error: err && err.message ? err.message : "Bad request",
        })
      );
    }
  });

  app.get("/config/versions", requireAuth, (req, res) => {
    const versions = configStore.listVersions({ limit: 100 });
    res.type("html").send(
      renderLayout({
        title: "版本 & 备份",
        user: req.user,
        content: renderVersionsPage({ versions }),
        notice: req.query.ok ? "已操作" : "",
      })
    );
  });

  app.post("/config/versions/:id/restore", requireAuth, (req, res) => {
    try {
      configStore.restoreVersion({ versionId: req.params.id, userId: req.user.id });
      res.redirect("/config/versions?ok=1");
    } catch (err) {
      res.status(err && err.statusCode ? err.statusCode : 400).type("html").send(
        renderLayout({
          title: "版本 & 备份",
          user: req.user,
          content: renderVersionsPage({ versions: configStore.listVersions({ limit: 100 }) }),
          error: err && err.message ? err.message : "Bad request",
        })
      );
    }
  });

  app.get("/config/export", requireAuth, (req, res) => {
    const encrypted = configStore.getEncryptedConfig();
    res.setHeader("content-type", "application/json; charset=utf-8");
    res.setHeader("content-disposition", "attachment; filename=\"hazuki-config.json\"");
    res.end(JSON.stringify(encrypted, null, 2));
  });

  app.get("/config/import", requireAuth, (req, res) => {
    res.type("html").send(
      renderLayout({
        title: "导入备份",
        user: req.user,
        content: renderImportPage(),
      })
    );
  });

  app.post("/config/import", requireAuth, (req, res) => {
    try {
      const raw = (req.body.configJson || "").toString();
      const parsed = JSON.parse(raw);
      const validated = AppConfigSchema.parse(parsed);

      // Save as a new version by updating config via restore-like path.
      // We reuse ConfigStore internal encryption rules by applying it as an "update" to the decrypted config.
      configStore.updateConfig({
        userId: req.user.id,
        note: "import",
        preserveEmptySecrets: false,
        updater: (cfg) => {
          // validated may contain encrypted secrets; we accept it as-is.
          return { ...cfg, ...validated };
        },
      });

      res.redirect("/config/versions?ok=1");
    } catch (err) {
      res.status(400).type("html").send(
        renderLayout({
          title: "导入备份",
          user: req.user,
          content: renderImportPage(),
          error: err && err.message ? err.message : "Bad request",
        })
      );
    }
  });

  const config = configStore.getDecryptedConfig();
  const port = config.ports.admin;

  const server = app.listen(port, "0.0.0.0", () => {
    // eslint-disable-next-line no-console
    console.log(`hazuki admin: http://0.0.0.0:${port}`);
  });

  return { app, server };
}

function buildWizardFormFromConfig(config) {
  const torcherinoWorkerSecretHeaderMapRedacted = Object.fromEntries(
    Object.entries(config.torcherino.workerSecretHeaderMap || {}).map(([k, v]) => [k, v ? "__SET__" : ""])
  );
  return {
    torcherinoDefaultTarget: (config.torcherino.defaultTarget || "").toString(),
    torcherinoHostMappingJson: JSON.stringify(config.torcherino.hostMapping || {}, null, 2),
    torcherinoWorkerSecretHeaders: (config.torcherino.workerSecretHeaders || []).join(", "),
    torcherinoWorkerSecretHeaderMapJson: JSON.stringify(torcherinoWorkerSecretHeaderMapRedacted, null, 2),
    cdnjsDefaultGhUser: (config.cdnjs.defaultGhUser || "").toString(),
    cdnjsAllowedGhUsers: (config.cdnjs.allowedGhUsers || []).join(", "),
    cdnjsAssetUrl: (config.cdnjs.assetUrl || "").toString(),
    cdnjsRedisHost: (config.cdnjs.redis.host || "").toString(),
    cdnjsRedisPort: String(config.cdnjs.redis.port || 6379),
    gitUpstreamPath: (config.git.upstreamPath || "").toString(),
  };
}

function buildWizardFormFromBody(body, currentConfig) {
  const take = (value, fallback) => {
    if (value === undefined || value === null) return fallback;
    return value.toString();
  };

  const torcherinoHostMappingJsonDefault = JSON.stringify(currentConfig.torcherino.hostMapping || {}, null, 2);
  const torcherinoWorkerSecretHeadersDefault = (currentConfig.torcherino.workerSecretHeaders || []).join(", ");
  const torcherinoWorkerSecretHeaderMapJsonDefault = JSON.stringify(
    Object.fromEntries(
      Object.entries(currentConfig.torcherino.workerSecretHeaderMap || {}).map(([k, v]) => [k, v ? "__SET__" : ""])
    ),
    null,
    2
  );
  const cdnjsAllowedGhUsersDefault = (currentConfig.cdnjs.allowedGhUsers || []).join(", ");

  return {
    torcherinoDefaultTarget: take(body.torcherinoDefaultTarget, "").trim(),
    torcherinoHostMappingJson: take(body.torcherinoHostMappingJson, torcherinoHostMappingJsonDefault),
    torcherinoWorkerSecretHeaders: take(body.torcherinoWorkerSecretHeaders, torcherinoWorkerSecretHeadersDefault).trim(),
    torcherinoWorkerSecretHeaderMapJson: take(
      body.torcherinoWorkerSecretHeaderMapJson,
      torcherinoWorkerSecretHeaderMapJsonDefault
    ),
    cdnjsDefaultGhUser: take(body.cdnjsDefaultGhUser, "").trim(),
    cdnjsAllowedGhUsers: take(body.cdnjsAllowedGhUsers, cdnjsAllowedGhUsersDefault).trim(),
    cdnjsAssetUrl: take(body.cdnjsAssetUrl, currentConfig.cdnjs.assetUrl).trim() || currentConfig.cdnjs.assetUrl,
    cdnjsRedisHost: take(body.cdnjsRedisHost, currentConfig.cdnjs.redis.host).trim() || currentConfig.cdnjs.redis.host,
    cdnjsRedisPort:
      take(body.cdnjsRedisPort, String(currentConfig.cdnjs.redis.port || 6379)).trim() ||
      String(currentConfig.cdnjs.redis.port || 6379),
    gitUpstreamPath: take(body.gitUpstreamPath, currentConfig.git.upstreamPath).trim() || currentConfig.git.upstreamPath,
  };
}

function requireAuth(req, res, next) {
  if (!req.hasUsers) return res.redirect("/setup");
  if (req.user) return next();
  return res.redirect("/login");
}

function readCookie(cookieHeader, name) {
  const raw = (cookieHeader || "").toString();
  if (!raw) return "";
  const parts = raw.split(";").map((p) => p.trim());
  for (const part of parts) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    const k = part.slice(0, eq).trim();
    const v = part.slice(eq + 1).trim();
    if (k === name) return decodeURIComponent(v);
  }
  return "";
}

function parseCsv(value) {
  return (value || "")
    .toString()
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function normalizeHeaderName(value) {
  return (value || "").toString().trim().toLowerCase();
}

function isValidHeaderName(name) {
  return /^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(name);
}

function parseHeaderNamesCsv(value) {
  const names = parseCsv(value)
    .map(normalizeHeaderName)
    .filter(Boolean);

  for (const name of names) {
    if (!isValidHeaderName(name)) {
      throw new Error("WORKER_SECRET_HEADERS：Header 名称不合法");
    }
  }

  return Array.from(new Set(names));
}

function mergeSecretHeaderMap({ input, current }) {
  const currentMap =
    current && typeof current === "object" && !Array.isArray(current) ? current : {};

  const out = {};
  const inputMap =
    input && typeof input === "object" && !Array.isArray(input) ? input : {};

  for (const [rawName, rawValue] of Object.entries(inputMap)) {
    const headerName = normalizeHeaderName(rawName);
    if (!headerName) continue;
    if (!isValidHeaderName(headerName)) {
      throw new Error("WORKER_SECRET_HEADER_MAP：Header 名称不合法");
    }

    let value = "";
    if (rawValue === "__SET__") {
      value = (currentMap[headerName] || "").toString();
    } else if (rawValue === undefined || rawValue === null || rawValue === "") {
      value = "";
    } else if (typeof rawValue !== "string") {
      throw new Error("WORKER_SECRET_HEADER_MAP：value 必须是字符串");
    } else {
      value = rawValue;
    }

    if (!value) continue;
    out[headerName] = value;
  }

  return out;
}

function parseBoolean(value, fallback) {
  if (value === undefined || value === null || value === "") return fallback;
  const v = value.toString().trim().toLowerCase();
  if (["1", "true", "yes", "y", "on"].includes(v)) return true;
  if (["0", "false", "no", "n", "off"].includes(v)) return false;
  return fallback;
}

function normalizePath(value) {
  const s = (value || "").toString().trim();
  if (!s) return "/";
  if (!s.startsWith("/")) return `/${s}`;
  return s.endsWith("/") ? s.slice(0, -1) : s;
}

function parseJsonObject(value) {
  const raw = (value || "").toString().trim();
  if (!raw) return {};
  const parsed = JSON.parse(raw);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("JSON must be an object");
  }
  return parsed;
}

function isSecureRequest(req) {
  const xfProto = (req.headers["x-forwarded-proto"] || "").toString();
  const proto = xfProto.split(",")[0].trim().toLowerCase();
  return proto === "https";
}

function bootstrapAdminIfNeeded({ db }) {
  ensureBootstrapAdmin({
    db,
    username: process.env.HAZUKI_ADMIN_USERNAME,
    password: process.env.HAZUKI_ADMIN_PASSWORD,
  });
}

module.exports = { startAdminServer, bootstrapAdminIfNeeded };
