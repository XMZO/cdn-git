"use strict";

const http = require("node:http");
const https = require("node:https");

function normalizeHeaderName(value) {
  return (value || "").toString().trim().toLowerCase();
}

function isValidHeaderName(name) {
  return /^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(name);
}

function normalizeHeaderMap(map) {
  if (!map || typeof map !== "object" || Array.isArray(map)) return {};
  const out = {};
  for (const [k, v] of Object.entries(map)) {
    const headerName = normalizeHeaderName(k);
    if (!headerName || !isValidHeaderName(headerName)) continue;
    const headerValue = (v ?? "").toString();
    if (!headerValue) continue;
    out[headerName] = headerValue;
  }
  return out;
}

function startTorcherinoServer({ configStore }) {
  let runtime = buildRuntimeConfig(configStore.getDecryptedConfig());
  configStore.on("changed", (cfg) => {
    runtime = buildRuntimeConfig(cfg);
  });

  const server = http.createServer((req, res) => {
    proxyRequest({ req, res, runtime }).catch((err) => {
      // eslint-disable-next-line no-console
      console.error("torcherino proxy error:", err && err.message ? err.message : err);
      if (!res.headersSent) res.writeHead(502, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("Bad Gateway");
    });
  });

  server.listen(runtime.port, "0.0.0.0", () => {
    // eslint-disable-next-line no-console
    console.log(`torcherino: http://0.0.0.0:${runtime.port}`);
  });

  return { server };
}

function buildRuntimeConfig(appConfig) {
  return {
    port: Number(appConfig.ports.torcherino) || 3000,
    defaultTarget: (appConfig.torcherino.defaultTarget || "").toString(),
    hostMapping: appConfig.torcherino.hostMapping || {},
    workerSecretKey: (appConfig.torcherino.workerSecretKey || "").toString(),
    workerSecretHeaders: (appConfig.torcherino.workerSecretHeaders || [])
      .map(normalizeHeaderName)
      .filter((h) => h && isValidHeaderName(h)),
    workerSecretHeaderMap: normalizeHeaderMap(appConfig.torcherino.workerSecretHeaderMap),
  };
}

function rewriteBody(body, reqOrigin) {
  const pagesDevPattern = /https?:\/\/[^/"'\s]*\.pages\.dev/gi;
  const hfSpacePattern = /https?:\/\/[^/"'\s]*\.hf\.space/gi;

  return body.replace(pagesDevPattern, reqOrigin).replace(hfSpacePattern, reqOrigin);
}

async function proxyRequest({ req, res, runtime }) {
  const path = (req.url || "").toString().split("?")[0];
  if ((req.method === "GET" || req.method === "HEAD") && path === "/_hazuki/health") {
    const payload = {
      ok: true,
      service: "torcherino",
      port: runtime.port,
      defaultTargetSet: !!runtime.defaultTarget,
      hostMappingCount: Object.keys(runtime.hostMapping || {}).length,
      workerSecretSet: !!runtime.workerSecretKey,
      workerSecretHeaders: runtime.workerSecretHeaders,
      workerSecretHeaderMapKeys: Object.keys(runtime.workerSecretHeaderMap || {}),
      time: new Date().toISOString(),
    };
    res.writeHead(200, { "Content-Type": "application/json; charset=utf-8" });
    if (req.method === "HEAD") return res.end();
    res.end(JSON.stringify(payload, null, 2));
    return;
  }

  const reqHost = (req.headers.host || "localhost").toString().split(":")[0];
  const targetHost = runtime.hostMapping[reqHost] || runtime.defaultTarget;
  if (!targetHost) {
    res.writeHead(502, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Bad Gateway: DEFAULT_TARGET is empty");
    return;
  }

  const targetUrl = new URL(req.url, `https://${targetHost}`);
  const reqOrigin = `${(req.headers["x-forwarded-proto"] || "http").toString()}://${(req.headers.host || "").toString()}`;

  const headers = { ...req.headers };
  headers.host = targetHost;
  delete headers.connection;
  delete headers["keep-alive"];
  delete headers["accept-encoding"];

  if (runtime.workerSecretKey) {
    const headerNames =
      runtime.workerSecretHeaders && runtime.workerSecretHeaders.length > 0
        ? runtime.workerSecretHeaders
        : ["x-forwarded-by-worker"];
    for (const headerName of headerNames) {
      headers[headerName] = runtime.workerSecretKey;
    }
  }
  for (const [headerName, headerValue] of Object.entries(runtime.workerSecretHeaderMap || {})) {
    headers[headerName] = headerValue;
  }

  const options = {
    hostname: targetHost,
    port: 443,
    path: targetUrl.pathname + targetUrl.search,
    method: req.method,
    headers,
  };

  await new Promise((resolve) => {
    const proxyReq = https.request(options, (proxyRes) => {
      const contentType = (proxyRes.headers["content-type"] || "").toString();

      if (proxyRes.statusCode >= 300 && proxyRes.statusCode < 400) {
        const location = proxyRes.headers.location;
        if (location) {
          proxyRes.headers.location = rewriteBody(location.toString(), reqOrigin);
        }
        res.writeHead(proxyRes.statusCode, proxyRes.headers);
        res.end();
        return resolve();
      }

      if (contentType.includes("application/json") || contentType.includes("text/html")) {
        let body = "";
        proxyRes.on("data", (chunk) => (body += chunk));
        proxyRes.on("end", () => {
          const rewritten = rewriteBody(body, reqOrigin);
          const newHeaders = { ...proxyRes.headers };
          delete newHeaders["content-length"];
          delete newHeaders["transfer-encoding"];
          newHeaders["content-length"] = Buffer.byteLength(rewritten);
          res.writeHead(proxyRes.statusCode, newHeaders);
          res.end(rewritten);
          resolve();
        });
        return;
      }

      res.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.pipe(res);
      proxyRes.on("end", resolve);
    });

    proxyReq.on("error", () => {
      res.writeHead(502, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("Bad Gateway");
      resolve();
    });

    req.pipe(proxyReq);
  });
}

module.exports = { startTorcherinoServer };
