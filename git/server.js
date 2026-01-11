"use strict";

const http = require("node:http");
const { Readable } = require("node:stream");
const { pipeline } = require("node:stream/promises");

require("dotenv").config();

const config = loadConfig(process.env);

const server = http.createServer(async (req, res) => {
  try {
    await handleRequest(req, res);
  } catch (err) {
    if (!res.headersSent) {
      res.statusCode = 502;
      res.setHeader("content-type", "text/plain; charset=utf-8");
    }
    res.end("Bad gateway");
    console.error(err);
  }
});

server.listen(config.port, config.host, () => {
  console.log(`listening on http://${config.host}:${config.port}`);
});

async function handleRequest(req, res) {
  const originalHost = getOriginalHost(req);
  const originalProto = getOriginalProto(req);
  const originalUrl = new URL(req.url, `${originalProto}://${originalHost}`);
  const requestOrigin = (req.headers.origin || "").toString();

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

  const upstreamDomain = isDesktopDevice(userAgent)
    ? config.upstream
    : config.upstreamMobile;

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
    const rewritten = applyReplacements(
      upstreamText,
      upstreamDomain,
      originalHost,
      config.replaceDict
    );
    res.end(rewritten);
    return;
  }

  if (!upstreamResponse.body) {
    res.end();
    return;
  }

  await pipeline(Readable.fromWeb(upstreamResponse.body), res);
}

function loadConfig(env) {
  const upstream = (env.UPSTREAM || "raw.githubusercontent.com").toString();
  const upstreamMobile = (env.UPSTREAM_MOBILE || upstream).toString();
  const upstreamPath = normalizeUpstreamPath(
    (env.UPSTREAM_PATH || "/XMZO/pic/main").toString()
  );

  const githubToken = (env.GITHUB_TOKEN || "").toString();
  const githubAuthScheme = (env.GITHUB_AUTH_SCHEME || "token").toString();

  const https = parseBoolean(env.UPSTREAM_HTTPS, true);
  const disableCache = parseBoolean(env.DISABLE_CACHE, false);
  const cacheControl = (env.CACHE_CONTROL || "").toString().trim();
  const cacheControlMedia = (
    env.CACHE_CONTROL_MEDIA || "public, max-age=43200000"
  ).toString();
  const cacheControlText = (env.CACHE_CONTROL_TEXT || "public, max-age=60").toString();

  const corsOrigins = parseCorsOrigins(env.CORS_ORIGIN);
  let corsAllowCredentials = parseBoolean(env.CORS_ALLOW_CREDENTIALS, false);
  const corsExposeHeaders = (
    env.CORS_EXPOSE_HEADERS ||
    "Accept-Ranges, Content-Length, Content-Range, ETag, Cache-Control, Last-Modified"
  ).toString();

  const blockedRegions = parseCsvList(env.BLOCKED_REGION);
  const blockedIpAddresses =
    env.BLOCKED_IP_ADDRESS !== undefined && env.BLOCKED_IP_ADDRESS !== null
      ? parseCsvList(env.BLOCKED_IP_ADDRESS)
      : ["0.0.0.0", "127.0.0.1"];

  const replaceDict = parseJsonObject(env.REPLACE_DICT, {
    $upstream: "$custom_domain",
  });

  const port = parsePort(env.PORT, 3000);
  const host = (env.HOST || "127.0.0.1").toString();

  if (!githubToken) {
    console.warn("warning: GITHUB_TOKEN is empty; private repos may fail.");
  }

  if (corsAllowCredentials && corsOrigins.kind === "any") {
    corsAllowCredentials = false;
    console.warn(
      "warning: CORS_ALLOW_CREDENTIALS=true is invalid with CORS_ORIGIN='*'; disabling credentials."
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

function normalizeUpstreamPath(value) {
  const trimmed = value.trim();
  if (!trimmed) return "/";
  const withLeading = trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
  return withLeading.endsWith("/") ? withLeading.slice(0, -1) : withLeading;
}

function parsePort(value, fallback) {
  const n = Number.parseInt((value || "").toString(), 10);
  return Number.isFinite(n) && n > 0 && n < 65536 ? n : fallback;
}

function parseBoolean(value, fallback) {
  if (value === undefined || value === null || value === "") return fallback;
  const v = value.toString().trim().toLowerCase();
  if (["1", "true", "yes", "y", "on"].includes(v)) return true;
  if (["0", "false", "no", "n", "off"].includes(v)) return false;
  return fallback;
}

function parseCsvList(value) {
  if (value === undefined || value === null) return [];
  const raw = value.toString().trim();
  if (!raw) return [];
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
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

function buildUpstreamRequestHeaders({
  req,
  upstreamDomain,
  originalHost,
  originalProto,
  githubToken,
  githubAuthScheme,
}) {
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

  // Ensure upstream host is correct (undici sets it from URL; this is just explicit).
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

    // When we rewrite HTML, content-length may be wrong.
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
    headers["x-pjax-url"] = headers["x-pjax-url"].replace(
      `//${upstreamDomain}`,
      `//${originalHost}`
    );
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

function computeCacheControl({
  disableCache,
  contentType,
  cacheControl,
  cacheControlMedia,
  cacheControlText,
}) {
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

  const requestHeaders = (req.headers["access-control-request-headers"] || "")
    .toString()
    .trim();
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
      key === "$upstream"
        ? upstreamDomain
        : key === "$custom_domain"
          ? hostName
          : key;

    const resolvedValue =
      rawValue === "$upstream"
        ? upstreamDomain
        : rawValue === "$custom_domain"
          ? hostName
          : rawValue;

    if (!resolvedKey) continue;
    out = out.replaceAll(String(resolvedKey), String(resolvedValue));
  }
  return out;
}
