"use strict";

const express = require("express");
const compression = require("compression");
const Redis = require("ioredis");

// 缓存时间配置（秒）
const CACHE_CONFIG = {
  js: 2592000,
  css: 2592000,
  png: 2592000,
  jpg: 2592000,
  jpeg: 2592000,
  gif: 2592000,
  svg: 2592000,
  ico: 2592000,
  woff: 2592000,
  woff2: 2592000,
  ttf: 2592000,
  eot: 2592000,
  webp: 2592000,
  moc3: 2592000,
  map: 2592000,
  cur: 2592000,
  mp4: 604800,
  mp3: 604800,
  pdf: 604800,
  json: 86400,
  xml: 86400,
  txt: 86400,
  html: 3600,
  default: 86400,
};

function getCacheTTL(filePath) {
  const match = filePath.match(/\.([^./?#]+)(?:[?#]|$)/);
  const ext = match ? match[1].toLowerCase() : null;
  return CACHE_CONFIG[ext] || CACHE_CONFIG.default;
}

function buildRuntimeConfig(appConfig) {
  const allowed = (appConfig.cdnjs.allowedGhUsers || [])
    .map((u) => u.trim())
    .filter(Boolean);
  const allowedSet = new Set(allowed.map((u) => u.toLowerCase()));

  return {
    port: appConfig.ports.cdnjs,
    assetUrl: appConfig.cdnjs.assetUrl,
    allowedUsers: allowedSet,
    defaultUser: appConfig.cdnjs.defaultGhUser || "",
    redis: {
      host: appConfig.cdnjs.redis.host,
      port: Number(appConfig.cdnjs.redis.port) || 6379,
    },
  };
}

function createRedisClient(redisConfig) {
  const redis = new Redis({
    host: redisConfig.host,
    port: redisConfig.port,
    maxRetriesPerRequest: 3,
    lazyConnect: true,
    enableOfflineQueue: false,
  });
  redis.on("error", (err) => {
    // eslint-disable-next-line no-console
    console.error("cdnjs redis error:", err.message || err);
  });
  return redis;
}

function startCdnjsServer({ configStore }) {
  const app = express();
  app.disable("x-powered-by");
  app.use(compression());

  let runtime = buildRuntimeConfig(configStore.getDecryptedConfig());
  let redis = createRedisClient(runtime.redis);

  const connectRedis = async () => {
    try {
      await redis.connect();
      // eslint-disable-next-line no-console
      console.log(`cdnjs redis: connected to ${runtime.redis.host}:${runtime.redis.port}`);
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error("cdnjs redis connect failed:", err && err.message ? err.message : err);
    }
  };
  void connectRedis();

  configStore.on("changed", (cfg) => {
    const next = buildRuntimeConfig(cfg);
    const redisChanged = next.redis.host !== runtime.redis.host || next.redis.port !== runtime.redis.port;
    runtime = next;
    if (redisChanged) {
      try {
        redis.disconnect();
      } catch {
        // ignore
      }
      redis = createRedisClient(runtime.redis);
      void connectRedis();
    }
  });

  app.get("/_hazuki/health", (req, res) => {
    res.type("application/json; charset=utf-8").send(
      JSON.stringify(
        {
          ok: true,
          service: "cdnjs",
          port: runtime.port,
          assetUrl: runtime.assetUrl,
          defaultUserSet: !!runtime.defaultUser,
          allowedUsersCount: runtime.allowedUsers.size,
          redis: {
            host: runtime.redis.host,
            port: runtime.redis.port,
            status: redis.status || "unknown",
          },
          time: new Date().toISOString(),
        },
        null,
        2
      )
    );
  });

  app.get(/^\/gh\/([^/]+)\/(.+)$/, async (req, res) => {
    const ghUser = req.params[0];
    const filePath = req.params[1];

    if (!runtime.allowedUsers.has(ghUser.toLowerCase())) {
      return res.status(403).type("text/plain; charset=utf-8").send(
        `Access denied: User "${ghUser}" is not authorized`
      );
    }

    await fetchWithCache({
      redis,
      cdnUrl: `${runtime.assetUrl}/gh/${ghUser}/${filePath}`,
      reqPath: req.path,
      res,
    });
  });

  app.get(/^\/(.*)$/, async (req, res) => {
    const reqPath = req.params[0];
    if (reqPath === "works") return res.type("text/plain; charset=utf-8").send("it works");
    if (!runtime.defaultUser) {
      return res.status(400).type("text/plain; charset=utf-8").send("DEFAULT_GH_USER is empty");
    }
    await fetchWithCache({
      redis,
      cdnUrl: `${runtime.assetUrl}/gh/${runtime.defaultUser}/${reqPath}`,
      reqPath: req.path,
      res,
    });
  });

  const server = app.listen(runtime.port, "0.0.0.0", () => {
    // eslint-disable-next-line no-console
    console.log(`cdnjs: http://0.0.0.0:${runtime.port}`);
  });

  return { app, server };
}

async function fetchWithCache({ redis, cdnUrl, reqPath, res }) {
  try {
    let cached = null;
    let cachedType = null;
    try {
      cached = await redis.getBuffer(cdnUrl);
      cachedType = await redis.get(`${cdnUrl}:type`);
    } catch {
      // Redis unavailable: treat as cache miss.
    }

    if (cached && cachedType) {
      res.set("X-Proxy-Cache", "HIT");
      res.set("Content-Type", cachedType);
      return res.send(cached);
    }

    const response = await fetch(cdnUrl);
    if (!response.ok) {
      res.set("X-Proxy-Cache", "BYPASS");
      return res.status(response.status).send(await response.text());
    }

    const body = Buffer.from(await response.arrayBuffer());
    const ct = response.headers.get("content-type") || "application/octet-stream";
    const ttl = getCacheTTL(reqPath);

    try {
      redis.setex(cdnUrl, ttl, body).catch(() => {});
      redis.setex(`${cdnUrl}:type`, ttl, ct).catch(() => {});
    } catch {
      // ignore
    }

    res.set({
      "X-Proxy-Cache": "MISS",
      "Cache-Control": `public, max-age=${ttl}`,
      "Content-Type": ct,
    });
    return res.send(body);
  } catch (error) {
    return res.status(502).type("text/plain; charset=utf-8").send("Fetch error: " + error.message);
  }
}

module.exports = { startCdnjsServer };
