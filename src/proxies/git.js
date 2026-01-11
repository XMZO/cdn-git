"use strict";

const http = require("node:http");
const { Readable } = require("node:stream");
const { pipeline } = require("node:stream/promises");

function startGitServer({ configStore }) {
  let runtime = buildRuntimeConfig(configStore.getDecryptedConfig());

  configStore.on("changed", (cfg) => {
    runtime = buildRuntimeConfig(cfg);
  });

  const server = http.createServer(async (req, res) => {
    try {
      await handleRequest(req, res, runtime);
    } catch (err) {
      if (!res.headersSent) {
        res.statusCode = 502;
        res.setHeader("content-type", "text/plain; charset=utf-8");
      }
      res.end("Bad gateway");
      // eslint-disable-next-line no-console
      console.error(err);
    }
  });

  server.listen(runtime.port, runtime.host, () => {
    // eslint-disable-next-line no-console
    console.log(`git: http://${runtime.host}:${runtime.port}`);
  });

  return { server };
}

function buildRuntimeConfig(appConfig) {
  const upstream = (appConfig.git.upstream || "raw.githubusercontent.com").toString();
  const upstreamMobile = (appConfig.git.upstreamMobile || upstream).toString();
  const upstreamPath = normalizeUpstreamPath((appConfig.git.upstreamPath || "/").toString());

  const githubToken = (appConfig.git.githubToken || "").toString();
  const githubAuthScheme = (appConfig.git.githubAuthScheme || "token").toString();

  const https = !!appConfig.git.https;
  const disableCache = !!appConfig.git.disableCache;
  const cacheControl = (appConfig.git.cacheControl || "").toString().trim();
  const cacheControlMedia = (appConfig.git.cacheControlMedia || "public, max-age=43200000").toString();
  const cacheControlText = (appConfig.git.cacheControlText || "public, max-age=60").toString();

  const corsOrigins = parseCorsOrigins(appConfig.git.corsOrigin);
  let corsAllowCredentials = !!appConfig.git.corsAllowCredentials;
  const corsExposeHeaders = (appConfig.git.corsExposeHeaders || "").toString();

  const blockedRegions = (appConfig.git.blockedRegions || []).map((s) => s.toUpperCase());
  const blockedIpAddresses = (appConfig.git.blockedIpAddresses || []).map((s) => s.trim()).filter(Boolean);

  const replaceDict = appConfig.git.replaceDict || { $upstream: "$custom_domain" };

  const port = Number(appConfig.ports.git) || 3002;
  const host = "0.0.0.0";

  if (corsAllowCredentials && corsOrigins.kind === "any") {
    corsAllowCredentials = false;
    // eslint-disable-next-line no-console
    console.warn(
      "git: CORS_ALLOW_CREDENTIALS=true is invalid with CORS_ORIGIN='*'; disabling credentials."
    );
  }

  return {
    upstream,
    upstreamMobile,
    upstreamPath,
    githubToken,
    githubAuthScheme,
    https,
    disableCache,
    cacheControl,
    cacheControlMedia,
    cacheControlText,
    corsOrigins,
    corsAllowCredentials,
    corsExposeHeaders,
    blockedRegions,
    blockedIpAddresses,
    replaceDict,
    port,
    host,
  };
}

async function handleRequest(req, res, config) {
  const originalHost = getOriginalHost(req);
  const originalProto = getOriginalProto(req);
  const originalUrl = new URL(req.url, `${originalProto}://${originalHost}`);
  const requestOrigin = (req.headers.origin || "").toString();

  if ((req.method === "GET" || req.method === "HEAD") && originalUrl.pathname === "/_hazuki/health") {
    const payload = {
      ok: true,
      service: "git",
      host: config.host,
      port: config.port,
      upstream: config.upstream,
      upstreamMobile: config.upstreamMobile,
      upstreamPath: config.upstreamPath,
      https: !!config.https,
      tokenSet: !!config.githubToken,
      disableCache: !!config.disableCache,
      corsOrigin: config.corsOrigins && config.corsOrigins.kind === "any" ? "*" : (config.corsOrigins || {}).allowList,
      time: new Date().toISOString(),
    };
    res.writeHead(200, { "content-type": "application/json; charset=utf-8" });
    if (req.method === "HEAD") return res.end();
    res.end(JSON.stringify(payload, null, 2));
    return;
  }

  const region = (req.headers["cf-ipcountry"] || "").toString().toUpperCase();
  const clientIp = getClientIp(req);
  const userAgent = (req.headers["user-agent"] || "").toString();

  if (config.blockedRegions.includes(region)) {
    res.writeHead(403, { "content-type": "text/plain; charset=utf-8" });
    res.end("Access denied: service is not available in your region yet.");
    return;
  }

  if (config.blockedIpAddresses.includes(clientIp)) {
    res.writeHead(403, { "content-type": "text/plain; charset=utf-8" });
    res.end("Access denied: your IP address is blocked.");
    return;
  }

  if (req.method === "OPTIONS") {
    const preflightHeaders = buildPreflightResponseHeaders({
      req,
      requestOrigin,
      config,
    });
    res.writeHead(204, preflightHeaders);
    res.end();
    return;
  }

  const upstreamDomain = isDesktopDevice(userAgent) ? config.upstream : config.upstreamMobile;

  const upstreamUrl = new URL(originalUrl.toString());
  upstreamUrl.protocol = config.https ? "https:" : "http:";
  upstreamUrl.hostname = upstreamDomain;
  upstreamUrl.port = "";

  if (upstreamUrl.pathname === "/" || upstreamUrl.pathname === "") {
    upstreamUrl.pathname = config.upstreamPath;
  } else {
    upstreamUrl.pathname = config.upstreamPath + upstreamUrl.pathname;
  }

  const requestHeaders = buildUpstreamRequestHeaders({
    req,
    upstreamDomain,
    originalHost,
    originalProto,
    githubToken: config.githubToken,
    githubAuthScheme: config.githubAuthScheme,
  });

  const abortController = new AbortController();
  req.on("close", () => abortController.abort());

  const fetchOptions = {
    method: req.method,
    headers: requestHeaders,
    redirect: "manual",
    signal: abortController.signal,
  };

  if (req.method !== "GET" && req.method !== "HEAD") {
    fetchOptions.body = req;
    fetchOptions.duplex = "half";
  }

  const upstreamResponse = await fetch(upstreamUrl, fetchOptions);

  const upstreamContentType = upstreamResponse.headers.get("content-type") || "";
  const shouldRewrite = shouldRewriteHtml(upstreamContentType);

  const cacheControl = computeCacheControl({
    disableCache: config.disableCache,
    contentType: upstreamContentType,
    cacheControl: config.cacheControl,
    cacheControlMedia: config.cacheControlMedia,
    cacheControlText: config.cacheControlText,
  });

  const responseHeaders = buildClientResponseHeaders({
    upstreamHeaders: upstreamResponse.headers,
    upstreamDomain,
    originalHost,
    requestPathname: originalUrl.pathname,
    cacheControl,
    requestOrigin,
    corsExposeHeaders: config.corsExposeHeaders,
    corsAllowCredentials: config.corsAllowCredentials,
    corsOrigins: config.corsOrigins,
    shouldRewrite,
  });

  res.writeHead(upstreamResponse.status, responseHeaders);

  if (req.method === "HEAD") {
    res.end();
    return;
  }

  if (shouldRewrite) {
    const upstreamText = await upstreamResponse.text();
    const rewritten = applyReplacements(upstreamText, upstreamDomain, originalHost, config.replaceDict);
    res.end(rewritten);
    return;
  }

  if (!upstreamResponse.body) {
    res.end();
    return;
  }

  await pipeline(Readable.fromWeb(upstreamResponse.body), res);
}

function normalizeUpstreamPath(value) {
  const trimmed = value.trim();
  if (!trimmed) return "/";
  const withLeading = trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
  return withLeading.endsWith("/") ? withLeading.slice(0, -1) : withLeading;
}

function parseCorsOrigins(value) {
  if (value === undefined || value === null || value === "") {
    return { kind: "any" };
  }
  const raw = value.toString().trim();
  if (!raw || raw === "*") return { kind: "any" };
  const allowList = raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  return { kind: "list", allowList };
}

function getOriginalHost(req) {
  const xfHost = (req.headers["x-forwarded-host"] || "").toString().trim();
  return xfHost || (req.headers.host || "localhost").toString();
}

function getOriginalProto(req) {
  const xfProto = (req.headers["x-forwarded-proto"] || "").toString();
  const v = xfProto.split(",")[0].trim();
  return v || "http";
}

function getClientIp(req) {
  const cf = (req.headers["cf-connecting-ip"] || "").toString().trim();
  if (cf) return cf;

  const xff = (req.headers["x-forwarded-for"] || "").toString();
  const first = xff.split(",")[0].trim();
  if (first) return first;

  return (req.socket.remoteAddress || "").toString();
}

function isDesktopDevice(userAgent) {
  const agents = ["Android", "iPhone", "SymbianOS", "Windows Phone", "iPad", "iPod"];
  for (const agent of agents) {
    if (userAgent.includes(agent)) return false;
  }
  return true;
}

function buildUpstreamRequestHeaders({ req, upstreamDomain, originalHost, originalProto, githubToken, githubAuthScheme }) {
  const headers = new Headers();

  for (const [key, value] of Object.entries(req.headers)) {
    if (value === undefined) continue;
    const lowerKey = key.toLowerCase();

    if (
      lowerKey === "connection" ||
      lowerKey === "keep-alive" ||
      lowerKey === "proxy-authenticate" ||
      lowerKey === "proxy-authorization" ||
      lowerKey === "authorization" ||
      lowerKey === "cookie" ||
      lowerKey === "te" ||
      lowerKey === "trailer" ||
      lowerKey === "transfer-encoding" ||
      lowerKey === "upgrade" ||
      lowerKey === "host" ||
      lowerKey === "accept-encoding" ||
      lowerKey === "content-length"
    ) {
      continue;
    }

    const headerValue = Array.isArray(value) ? value.join(",") : value.toString();
    headers.set(lowerKey, headerValue);
  }

  headers.set("referer", `${originalProto}://${originalHost}`);
  headers.set("accept-encoding", "identity");

  if (githubToken) {
    headers.set("authorization", `${githubAuthScheme} ${githubToken}`);
  }

  headers.set("host", upstreamDomain);
  return headers;
}

function buildClientResponseHeaders({
  upstreamHeaders,
  upstreamDomain,
  originalHost,
  requestPathname,
  cacheControl,
  requestOrigin,
  corsExposeHeaders,
  corsAllowCredentials,
  corsOrigins,
  shouldRewrite,
}) {
  const headers = {};

  upstreamHeaders.forEach((value, key) => {
    const lowerKey = key.toLowerCase();
    if (
      lowerKey === "content-security-policy" ||
      lowerKey === "content-security-policy-report-only" ||
      lowerKey === "clear-site-data" ||
      lowerKey === "content-encoding"
    ) {
      return;
    }

    if (lowerKey === "content-length" && shouldRewrite) return;
    headers[lowerKey] = value;
  });

  maybeFixOctetStreamContentType(headers, requestPathname);

  headers["cache-control"] = cacheControl;

  applyCorsHeaders(headers, {
    requestOrigin,
    corsOrigins,
    corsAllowCredentials,
    corsExposeHeaders,
  });

  if (typeof headers["x-pjax-url"] === "string") {
    headers["x-pjax-url"] = headers["x-pjax-url"].replace(`//${upstreamDomain}`, `//${originalHost}`);
  }

  if (typeof headers.vary === "string") {
    headers.vary = removeVaryHeaderValue(headers.vary, "authorization");
  }

  return headers;
}

function maybeFixOctetStreamContentType(headers, requestPathname) {
  const ct = (headers["content-type"] || "").toString().toLowerCase();
  if (!ct.startsWith("application/octet-stream")) return;

  const guessed = guessMimeFromPathname(requestPathname);
  if (!guessed) return;
  headers["content-type"] = guessed;
}

function guessMimeFromPathname(pathname) {
  const p = (pathname || "").toString();
  const base = p.split("/").pop() || "";
  const dot = base.lastIndexOf(".");
  if (dot === -1 || dot === base.length - 1) return "";
  const ext = base.slice(dot + 1).toLowerCase();

  const map = {
    webm: "video/webm",
    mp4: "video/mp4",
    webp: "image/webp",
    png: "image/png",
    jpg: "image/jpeg",
    jpeg: "image/jpeg",
    gif: "image/gif",
    svg: "image/svg+xml",
  };
  return map[ext] || "";
}

function shouldRewriteHtml(contentType) {
  const ct = (contentType || "").toString().toLowerCase();
  return ct.includes("text/html") && ct.includes("utf-8");
}

function computeCacheControl({ disableCache, contentType, cacheControl, cacheControlMedia, cacheControlText }) {
  if (disableCache) return "no-store";
  if (cacheControl) return cacheControl;

  const ct = (contentType || "").toString().toLowerCase();
  if (isMediaContentType(ct)) return cacheControlMedia;
  if (isTextContentType(ct)) return cacheControlText;
  return cacheControlMedia;
}

function isMediaContentType(contentType) {
  return (
    contentType.startsWith("image/") ||
    contentType.startsWith("video/") ||
    contentType.startsWith("audio/") ||
    contentType.startsWith("font/")
  );
}

function isTextContentType(contentType) {
  if (contentType.startsWith("text/")) return true;
  return (
    contentType.includes("application/json") ||
    contentType.includes("application/javascript") ||
    contentType.includes("application/x-javascript") ||
    contentType.includes("application/xml") ||
    contentType.includes("application/xhtml+xml") ||
    contentType.includes("application/yaml") ||
    contentType.includes("application/x-yaml") ||
    contentType.includes("application/toml") ||
    contentType.includes("application/vnd.apple.mpegurl") ||
    contentType.includes("application/x-mpegurl")
  );
}

function buildPreflightResponseHeaders({ req, requestOrigin, config }) {
  const headers = {};

  applyCorsHeaders(headers, {
    requestOrigin,
    corsOrigins: config.corsOrigins,
    corsAllowCredentials: config.corsAllowCredentials,
    corsExposeHeaders: config.corsExposeHeaders,
  });

  headers["access-control-allow-methods"] = "GET,HEAD,OPTIONS";

  const requestHeaders = (req.headers["access-control-request-headers"] || "").toString().trim();
  headers["access-control-allow-headers"] = requestHeaders || "Range";
  headers["access-control-max-age"] = "86400";

  appendVary(headers, "access-control-request-headers");

  headers["cache-control"] = "no-store";
  return headers;
}

function applyCorsHeaders(headers, { requestOrigin, corsOrigins, corsAllowCredentials, corsExposeHeaders }) {
  const originHeader = chooseCorsOrigin(requestOrigin, corsOrigins);
  if (!originHeader) return;

  headers["access-control-allow-origin"] = originHeader;
  if (corsAllowCredentials && originHeader !== "*") {
    headers["access-control-allow-credentials"] = "true";
  }
  if (corsExposeHeaders) {
    headers["access-control-expose-headers"] = corsExposeHeaders;
  }

  if (originHeader !== "*") {
    appendVary(headers, "origin");
  }
}

function chooseCorsOrigin(requestOrigin, corsOrigins) {
  if (!corsOrigins || corsOrigins.kind === "any") return "*";
  if (!requestOrigin) return "";
  return corsOrigins.allowList.includes(requestOrigin) ? requestOrigin : "";
}

function appendVary(headers, value) {
  const key = "vary";
  const existing = (headers[key] || "").toString().trim();
  if (!existing) {
    headers[key] = value;
    return;
  }
  const parts = existing
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (parts.some((p) => p.toLowerCase() === value.toLowerCase())) return;
  headers[key] = `${existing}, ${value}`;
}

function removeVaryHeaderValue(vary, toRemove) {
  const needle = toRemove.toLowerCase();
  const parts = (vary || "")
    .toString()
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .filter((p) => p.toLowerCase() !== needle);
  return parts.join(", ");
}

function applyReplacements(text, upstreamDomain, hostName, replaceDict) {
  let out = text;
  for (const [key, rawValue] of Object.entries(replaceDict || {})) {
    const resolvedKey =
      key === "$upstream" ? upstreamDomain : key === "$custom_domain" ? hostName : key;

    const resolvedValue =
      rawValue === "$upstream" ? upstreamDomain : rawValue === "$custom_domain" ? hostName : rawValue;

    if (!resolvedKey) continue;
    out = out.replaceAll(String(resolvedKey), String(resolvedValue));
  }
  return out;
}

module.exports = { startGitServer };
