(() => {
  const qs = (sel, root = document) => root.querySelector(sel);
  const qsa = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  const tKey = (key, fallback = "") => {
    const dict = window.HazukiI18n || {};
    const v = dict["js." + key] || dict[key];
    if (typeof v === "string" && v.trim() !== "") return v;
    return fallback || key;
  };

  const replaceAll = (s, search, replacement) => (s || "").toString().split(search).join(replacement);

  const tFmt = (key, fallback, vars) => {
    let out = tKey(key, fallback);
    if (!vars || typeof vars !== "object") return out;
    for (const [k, v] of Object.entries(vars)) {
      out = replaceAll(out, "{" + k + "}", String(v));
    }
    return out;
  };

  const canPjax = () =>
    typeof window.fetch === "function" &&
    typeof window.DOMParser === "function" &&
    !!(window.history && window.history.pushState);

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const nextFrame = () => new Promise((r) => requestAnimationFrame(() => r()));

  const waitTransitionEnd = async (el, maxMs) => {
    if (!el) return;
    if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      return;
    }
    await Promise.race([
      new Promise((resolve) => {
        const onEnd = (evt) => {
          if (evt.target !== el) return;
          cleanup();
        };
        const cleanup = () => {
          el.removeEventListener("transitionend", onEnd);
          resolve();
        };
        el.addEventListener("transitionend", onEnd);
        setTimeout(cleanup, maxMs);
      }),
      sleep(maxMs),
    ]);
  };

  const formatJson = (ta, msgEl) => {
    if (!ta) return;
    const raw = (ta.value || "").trim();
    if (!raw) return;
    try {
      const v = JSON.parse(raw);
      ta.value = JSON.stringify(v, null, 2);
      if (msgEl) msgEl.textContent = tKey("json.formatted", "Formatted");
    } catch (e) {
      if (msgEl) {
        msgEl.textContent =
          tKey("json.invalidPrefix", "Invalid JSON: ") +
          (e && e.message ? e.message : tKey("json.parseError", "parse error"));
      }
    }
  };

  const onFormatJsonClick = (e) => {
    const btn =
      e.target instanceof HTMLElement
        ? e.target.closest("[data-format-json]")
        : null;
    if (!btn) return;

    const sel = (btn.getAttribute("data-format-json") || "").trim();
    const row = btn.closest(".field");
    const msg = row ? qs(".json-msg", row) : null;
    const ta = sel ? qs(sel) : row ? row.querySelector("textarea") : null;

    if (ta instanceof HTMLTextAreaElement) {
      formatJson(ta, msg);
    }
  };

  const onTogglePassword = (e) => {
    const el = e.target;
    if (!(el instanceof HTMLInputElement)) return;
    if (!el.matches("[data-toggle-password]")) return;

    const targetSel = (el.getAttribute("data-toggle-password") || "").trim();
    const input = targetSel ? qs(targetSel) : null;
    if (!(input instanceof HTMLInputElement)) return;

    input.type = el.checked ? "text" : "password";
  };

  const extractExt = (requestPath) => {
    const base = ((requestPath || "").split("/").pop() || "").trim();
    const dot = base.lastIndexOf(".");
    if (dot <= 0 || dot === base.length - 1) return "";
    return base.slice(dot + 1).toLowerCase();
  };

  const guessMimeFromPath = (requestPath) => {
    const ext = extractExt(requestPath);
    if (!ext) return "";
    const map = {
      js: "application/javascript",
      mjs: "application/javascript",
      cjs: "application/javascript",
      jsx: "application/javascript",
      css: "text/css",
      html: "text/html",
      htm: "text/html",
      json: "application/json",
      map: "application/json",
      xml: "application/xml",
      yml: "application/x-yaml",
      yaml: "application/x-yaml",
      toml: "application/toml",
      txt: "text/plain",
      md: "text/plain",
      csv: "text/csv",
      wasm: "application/wasm",
      png: "image/png",
      jpg: "image/jpeg",
      jpeg: "image/jpeg",
      gif: "image/gif",
      webp: "image/webp",
      avif: "image/avif",
      svg: "image/svg+xml",
      ico: "image/x-icon",
      mp4: "video/mp4",
      webm: "video/webm",
      mp3: "audio/mpeg",
      wav: "audio/wav",
      ogg: "audio/ogg",
      m4a: "audio/mp4",
      woff2: "font/woff2",
      woff: "font/woff",
      ttf: "font/ttf",
      otf: "font/otf",
      eot: "application/vnd.ms-fontobject",
      m3u: "application/vnd.apple.mpegurl",
      m3u8: "application/vnd.apple.mpegurl",
    };
    return map[ext] || "";
  };

  const updateGitPreview = () => {
    const pathEl = qs("#gitPreviewPath");
    const outEl = qs("#gitPreviewUrl");
    const hintEl = qs("#gitPreviewHint");
    if (!(pathEl instanceof HTMLInputElement) || !(outEl instanceof HTMLInputElement) || !hintEl) return;

    const upstream = (qs('input[name="upstream"]')?.value || "").trim() || "raw.githubusercontent.com";

    let upstreamPath = (qs('input[name="upstreamPath"]')?.value || "").trim();
    if (!upstreamPath) upstreamPath = "/";
    if (!upstreamPath.startsWith("/")) upstreamPath = "/" + upstreamPath;
    if (upstreamPath.length > 1 && upstreamPath.endsWith("/")) upstreamPath = upstreamPath.slice(0, -1);

    const useHttps = !!(qs('input[name="upstreamHttps"]')?.checked);

    let reqPath = (pathEl.value || "").trim();
    if (!reqPath) reqPath = "/";
    if (!reqPath.startsWith("/")) reqPath = "/" + reqPath;

    const joinPath = (prefix, p) => {
      if (!p) p = "/";
      if (p === "/" || p === "") return prefix === "/" ? "" : prefix;
      if (prefix === "/" || prefix === "") return p;
      return prefix + p;
    };

    const scheme = useHttps ? "https" : "http";
    const finalPath = joinPath(upstreamPath, reqPath);
    outEl.value = scheme + "://" + upstream + finalPath;

    const t = guessMimeFromPath(reqPath);
    if (t) {
      hintEl.textContent =
        tKey("gitPreview.mimePrefix", "Guessed Content-Type: ") +
        t +
        tKey("gitPreview.mimeSuffix", " (used for cache classification / type fix)");
      return;
    }
    hintEl.textContent = tKey(
      "gitPreview.noExtHint",
      "No extension: Content-Type follows the upstream response."
    );
  };

  const cdnjsBuiltInDefaultTTL = 86400;
  const cdnjsBuiltInTTLByExt = {
    // Node defaults (kept for compatibility).
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

    // Extra common extensions (Go version).
    mjs: 2592000,
    cjs: 2592000,
    wasm: 2592000,
    avif: 2592000,
    apng: 2592000,
    bmp: 2592000,
    tif: 2592000,
    tiff: 2592000,
    otf: 2592000,
    svgz: 2592000,
    webm: 604800,
    m4a: 604800,
    aac: 604800,
    ogg: 604800,
    wav: 604800,
    flac: 604800,
    htm: 3600,
    md: 86400,
    yml: 86400,
    yaml: 86400,
    toml: 86400,
    jsonc: 86400,
  };

  const parseTTLOverrides = (raw) => {
    const maxTTLSeconds = 315360000; // 10 years
    const trimmed = (raw || "").toString().trim();
    if (!trimmed) return { ok: true, map: {} };

    const normExt = (ext) =>
      (ext || "")
        .toString()
        .trim()
        .toLowerCase()
        .replace(/^\./, "");

    if (trimmed.startsWith("{")) {
      try {
        const obj = JSON.parse(trimmed);
        if (!obj || typeof obj !== "object" || Array.isArray(obj)) {
          return {
            ok: false,
            err: tKey("ttlOverrides.errNotObject", "TTL Overrides must be a JSON object"),
            map: {},
          };
        }
        const out = {};
        for (const [k, v] of Object.entries(obj)) {
          const ext = normExt(k);
          if (!ext) continue;
          if (ext === "default") {
            return {
              ok: false,
              err: tKey(
                "ttlOverrides.errDefaultNotAllowed",
                "TTL Overrides: do not use default=...; use Default TTL above"
              ),
              map: {},
            };
          }
          const ttl = Number.parseInt(String(v), 10);
          if (!Number.isFinite(ttl) || ttl < 1 || ttl > maxTTLSeconds) {
            return {
              ok: false,
              err: tFmt(
                "ttlOverrides.errEntryRange",
                "TTL Overrides[{ext}] must be an integer between 1 and {max} (seconds)",
                { ext, max: maxTTLSeconds }
              ),
              map: {},
            };
          }
          out[ext] = ttl;
        }
        return { ok: true, map: out };
      } catch (e) {
        return {
          ok: false,
          err: tFmt(
            "ttlOverrides.errJsonInvalid",
            "TTL Overrides JSON invalid: {msg}",
            {
              msg: e && e.message ? e.message : tKey("json.parseError", "parse error"),
            }
          ),
          map: {},
        };
      }
    }

    const out = {};
    const lines = (raw || "").toString().split(/\r?\n/);
    for (let i = 0; i < lines.length; i += 1) {
      let s = (lines[i] || "").trim();
      if (!s || s.startsWith("#")) continue;

      const hashIdx = s.indexOf("#");
      if (hashIdx !== -1) s = s.slice(0, hashIdx).trim();
      if (!s) continue;

      const sepIdx = s.search(/[=:]/);
      if (sepIdx === -1) {
        return {
          ok: false,
          err: tFmt(
            "ttlOverrides.errLineFormat",
            "TTL Overrides line {line}: use ext=seconds format",
            { line: i + 1 }
          ),
          map: {},
        };
      }

      const ext = normExt(s.slice(0, sepIdx));
      if (!ext) {
        return {
          ok: false,
          err: tFmt("ttlOverrides.errLineEmptyExt", "TTL Overrides line {line}: empty extension", {
            line: i + 1,
          }),
          map: {},
        };
      }
      if (ext === "default") {
        return {
          ok: false,
          err: tFmt(
            "ttlOverrides.errLineDefaultNotAllowed",
            "TTL Overrides line {line}: do not use default=...; use Default TTL above",
            { line: i + 1 }
          ),
          map: {},
        };
      }

      const ttlRaw = s.slice(sepIdx + 1).trim();
      const ttl = Number.parseInt(ttlRaw, 10);
      if (!Number.isFinite(ttl) || ttl < 1 || ttl > maxTTLSeconds) {
        return {
          ok: false,
          err: tFmt(
            "ttlOverrides.errLineRange",
            "TTL Overrides line {line}: TTL must be an integer between 1 and {max} (seconds)",
            { line: i + 1, max: maxTTLSeconds }
          ),
          map: {},
        };
      }

      out[ext] = ttl;
    }
    return { ok: true, map: out };
  };

  const prettyTTL = (sec) => {
    const s = Number(sec) || 0;
    if (s >= 86400 && s % 86400 === 0) return tFmt("ttl.unitDay", "{n} days", { n: s / 86400 });
    if (s >= 3600 && s % 3600 === 0) return tFmt("ttl.unitHour", "{n} hours", { n: s / 3600 });
    if (s >= 60 && s % 60 === 0) return tFmt("ttl.unitMinute", "{n} minutes", { n: s / 60 });
    return tFmt("ttl.unitSecond", "{n} seconds", { n: s });
  };

  const updateCdnjsPreview = () => {
    const pathEl = qs("#cdnjsPreviewPath");
    const outEl = qs("#cdnjsPreviewUrl");
    const hintEl = qs("#cdnjsPreviewHint");
    if (!(pathEl instanceof HTMLInputElement) || !(outEl instanceof HTMLInputElement) || !hintEl) return;

    let p = (pathEl.value || "").trim();
    if (!p) p = "repo@ref/path/file.js";
    p = p.replace(/^\/+/, "");

    const asset = (qs('input[name="assetUrl"]')?.value || "").trim().replace(/\/+$/, "") || "https://cdn.jsdelivr.net";
    const defUser = (qs('input[name="defaultGhUser"]')?.value || "").trim();

    if (!defUser) {
      outEl.value = asset + "/gh/<DEFAULT_GH_USER>/" + p;
      hintEl.textContent = tKey(
        "cdnjsPreview.defaultUserMissing",
        "DEFAULT_GH_USER is empty: short paths /<path> will return 400."
      );
      return;
    }

    const defaultTTLRaw = (qs('input[name="defaultTTLSeconds"]')?.value || "").trim();
    const defaultTTL = (() => {
      const n = Number.parseInt(defaultTTLRaw, 10);
      return Number.isFinite(n) && n > 0 ? n : cdnjsBuiltInDefaultTTL;
    })();

    const overridesRaw = (qs('textarea[name="ttlOverrides"]')?.value || "").toString();
    const overrides = parseTTLOverrides(overridesRaw);
    if (!overrides.ok) {
      hintEl.textContent = overrides.err || tKey("ttlOverrides.parseFailed", "TTL Overrides parse failed");
    }

    const ttlByExt = { ...cdnjsBuiltInTTLByExt, ...(overrides.map || {}) };
    const ext = extractExt(p);
    const ttl = ext && ttlByExt[ext] ? ttlByExt[ext] : defaultTTL;

    outEl.value = asset + "/gh/" + defUser + "/" + p;
    const ttlPrefix = overrides.ok
      ? tKey("cdnjsPreview.ttlMatchedPrefix", "TTL match: ")
      : tKey("cdnjsPreview.ttlMatchedPrefixWithError", "TTL match (but overrides has errors): ");
    hintEl.textContent =
      ttlPrefix +
      prettyTTL(ttl) +
      tKey("cdnjsPreview.cacheControlPrefix", " (Cache-Control: public, max-age=") +
      ttl +
      tKey("cdnjsPreview.cacheControlSuffix", ")");
  };

  const updateTorcherinoPreview = () => {
    const hostEl = qs("#torcherinoPreviewHost");
    const pathEl = qs("#torcherinoPreviewPath");
    const targetEl = qs("#torcherinoPreviewTarget");
    const urlEl = qs("#torcherinoPreviewUrl");
    const hintEl = qs("#torcherinoPreviewHint");
    if (
      !(hostEl instanceof HTMLInputElement) ||
      !(pathEl instanceof HTMLInputElement) ||
      !(targetEl instanceof HTMLInputElement) ||
      !(urlEl instanceof HTMLInputElement) ||
      !hintEl
    ) {
      return;
    }

    const normHost = (h) => (h || "").toString().trim().toLowerCase();
    const normPath = (p) => {
      let v = (p || "").toString().trim();
      if (!v) v = "/";
      if (!v.startsWith("/")) v = "/" + v;
      return v;
    };

    const host = normHost(hostEl.value || "");
    const path = normPath(pathEl.value || "");
    const defTarget = (qs('input[name="defaultTarget"]')?.value || "").trim();

    const raw = (qs("#hostMappingJson")?.value || "").trim();
    let mapping = {};
    if (raw) {
      try {
        const v = JSON.parse(raw);
        if (!v || typeof v !== "object" || Array.isArray(v)) {
          targetEl.value = "";
          urlEl.value = "";
          hintEl.textContent = tKey(
            "torcherinoPreview.mappingNotObject",
            "HOST_MAPPING must be a JSON object"
          );
          return;
        }
        mapping = v;
      } catch (e) {
        targetEl.value = "";
        urlEl.value = "";
        hintEl.textContent = tFmt(
          "torcherinoPreview.mappingJsonInvalid",
          "HOST_MAPPING JSON invalid: {msg}",
          { msg: e && e.message ? e.message : tKey("json.parseError", "parse error") }
        );
        return;
      }
    }

    const mappingLower = {};
    for (const [k, v] of Object.entries(mapping || {})) {
      const kk = normHost(k);
      const vv = (v || "").toString().trim();
      if (!kk || !vv) continue;
      mappingLower[kk] = vv;
    }

    const fromMap = host && mappingLower[host] ? String(mappingLower[host]) : "";
    const target = (fromMap || defTarget || "").trim();

    if (!target) {
      targetEl.value = "";
      urlEl.value = "";
      hintEl.textContent = tKey(
        "torcherinoPreview.noTarget",
        "DEFAULT_TARGET is empty and HOST_MAPPING didn't match: requests will return 502."
      );
      return;
    }

    targetEl.value =
      target +
      (fromMap
        ? tKey("torcherinoPreview.fromMapSuffix", " (mapped)")
        : tKey("torcherinoPreview.defaultSuffix", " (default)"));
    urlEl.value = "https://" + target + path;
    hintEl.textContent = tKey(
      "torcherinoPreview.rewriteNotice",
      "Note: Torcherino rewrites *.pages.dev / *.hf.space in upstream responses to the current host."
    );
  };

  const refreshPage = ({ skipNav = false, pathname = "" } = {}) => {
    if (!skipNav) updateNavActive(pathname);
    updateGitPreview();
    updateCdnjsPreview();
    updateTorcherinoPreview();
  };

  const updateNavActive = (pathname) => {
    const path = (pathname || (window.location && window.location.pathname) || "").toString();
    if (!path) return;

    for (const a of qsa(".nav a")) {
      const href = (a.getAttribute("href") || "").trim();
      if (!href) continue;
      const active = href === path || (href !== "/" && path.startsWith(href + "/"));
      a.classList.toggle("active", active);
    }
  };

  const setNavPending = (pathname) => {
    const path = (pathname || (window.location && window.location.pathname) || "").toString();
    if (!path) return;

    document.body.classList.add("hz-loading");
    const root = qs("#pjax-root");
    if (root) {
      root.setAttribute("aria-busy", "true");
      root.classList.remove("hz-leave", "hz-enter");
    }

    for (const a of qsa(".nav a")) {
      const href = (a.getAttribute("href") || "").trim();
      if (!href) continue;
      const active = href === path || (href !== "/" && path.startsWith(href + "/"));
      a.classList.toggle("hz-pending", active);
    }
  };

  const clearNavPending = () => {
    document.body.classList.remove("hz-loading");
    const root = qs("#pjax-root");
    if (root) root.removeAttribute("aria-busy");

    for (const a of qsa(".nav a.hz-pending")) {
      a.classList.remove("hz-pending");
    }
  };

  let navAbortController = null;
  let navSeq = 0;

  const isSameLayout = (doc) => {
    const curHasSidebar = !!qs(".sidebar");
    const nextHasSidebar = !!(doc && doc.querySelector && doc.querySelector(".sidebar"));
    return curHasSidebar === nextHasSidebar;
  };

  const parseHtml = (html) => {
    try {
      const parser = new DOMParser();
      return parser.parseFromString(html, "text/html");
    } catch {
      return null;
    }
  };

  const applyDocToDom = (doc) => {
    const root = qs("#pjax-root");
    const nextRoot = doc ? doc.querySelector("#pjax-root") : null;
    if (!root || !nextRoot) return false;

    root.innerHTML = nextRoot.innerHTML;

    const page = (doc.body && doc.body.getAttribute("data-page")) || "";
    if (page) {
      document.body.setAttribute("data-page", page);
    }

    const title = doc.title || "";
    if (title) {
      document.title = title;
      const headTitle = qs(".topbar .title");
      if (headTitle) {
        const stripped = title.replace(/\s*-\s*Hazuki\s*$/, "");
        headTitle.textContent = stripped || headTitle.textContent;
      }
    }

    const mobileNav = qs(".mobile-nav");
    if (mobileNav && "open" in mobileNav) {
      mobileNav.open = false;
    }

    // Avoid nav highlight flicker: during PJAX navigation, the URL may not be
    // updated yet (pushState happens later). Nav state is handled by navigate().
    refreshPage({ skipNav: true });
    return true;
  };

  const swapWithTransition = async (doc, isValid) => {
    const root = qs("#pjax-root");
    let ok = false;
    const apply = () => {
      if (typeof isValid === "function" && !isValid()) return;
      ok = applyDocToDom(doc);
    };

    if (!root) {
      apply();
      return ok;
    }

    if (typeof isValid === "function" && !isValid()) {
      return false;
    }

    if (typeof document.startViewTransition === "function") {
      try {
        const vt = document.startViewTransition(() => apply());
        if (vt && vt.finished) {
          await vt.finished;
        }
        return ok;
      } catch {
        // fall through
      }
    }

    root.classList.add("hz-leave");
    await waitTransitionEnd(root, 220);
    if (typeof isValid === "function" && !isValid()) {
      root.classList.remove("hz-leave");
      return false;
    }
    apply();
    root.classList.remove("hz-leave");
    root.classList.add("hz-enter");
    await nextFrame();
    root.classList.remove("hz-enter");

    return ok;
  };

  const shouldBypassPjax = (url, a) => {
    if (!url) return true;
    if (!canPjax()) return true;

    if (a) {
      if (a.hasAttribute("download")) return true;
      const target = (a.getAttribute("target") || "").toLowerCase();
      if (target && target !== "_self") return true;
      if ((a.getAttribute("rel") || "").toLowerCase().includes("external")) return true;
      if ((a.getAttribute("data-no-pjax") || "").trim() !== "") return true;
    }

    if (url.origin !== window.location.origin) return true;
    if (url.hash && url.pathname === window.location.pathname && url.search === window.location.search) return true;

    const p = url.pathname || "";
    if (p.startsWith("/assets/")) return true;
    if (p === "/favicon.ico" || p === "/fav.png") return true;
    if (p === "/lang") return true; // needs full reload to update layout translations
    if (p === "/config/export") return true; // download

    return false;
  };

  const navigate = async (url, { replace = false, addHistory = true } = {}) => {
    if (!url) return;
    if (!canPjax()) {
      window.location.href = url.href;
      return;
    }

    const mySeq = (navSeq += 1);

    if (navAbortController && typeof navAbortController.abort === "function") {
      try {
        navAbortController.abort();
      } catch {
        // ignore
      }
    }

    let controller = null;
    let signal;
    if (typeof AbortController === "function") {
      controller = new AbortController();
      navAbortController = controller;
      signal = controller.signal;
    } else {
      navAbortController = null;
    }

    updateNavActive(url.pathname);
    setNavPending(url.pathname);

    try {
      const fetchOpts = {
        method: "GET",
        headers: { Accept: "text/html", "X-Hazuki-Pjax": "1" },
        credentials: "same-origin",
      };
      if (signal) fetchOpts.signal = signal;

      const resp = await fetch(url.href, fetchOpts);
      if (mySeq !== navSeq) return;
      if (!resp.ok) {
        window.location.href = url.href;
        return;
      }

      const ct = (resp.headers.get("content-type") || "").toLowerCase();
      if (!ct.includes("text/html")) {
        window.location.href = url.href;
        return;
      }

      const html = await resp.text();
      if (mySeq !== navSeq) return;
      const doc = parseHtml(html);
      if (!doc || !doc.documentElement) {
        window.location.href = url.href;
        return;
      }

      if (!isSameLayout(doc)) {
        window.location.href = resp.url || url.href;
        return;
      }

      const finalURL = new URL(resp.url || url.href, window.location.href);

      const swapped = await swapWithTransition(doc, () => mySeq === navSeq);
      if (mySeq !== navSeq) return;
      if (!swapped) {
        window.location.href = finalURL.href;
        return;
      }

      if (addHistory) {
        const st = { href: finalURL.href };
        if (replace) window.history.replaceState(st, "", finalURL.href);
        else window.history.pushState(st, "", finalURL.href);
      }
      updateNavActive(finalURL.pathname);
      window.scrollTo(0, 0);
    } catch {
      if (controller && controller.signal && controller.signal.aborted) {
        return;
      }
      window.location.href = url.href;
    } finally {
      if (mySeq === navSeq) {
        clearNavPending();
      }
    }
  };

  const confirmModal = ({ title, detail, okText } = {}) => {
    const t = (title || tKey("modal.confirmTitle", "确认操作")).toString();
    const d = (detail || "").toString();

    const root = qs("#hz-modal");
    const titleEl = root ? qs("#hz-modal-title", root) : null;
    const detailEl = root ? qs("#hz-modal-detail", root) : null;
    const okBtn = root ? qs("[data-hz-modal-ok]", root) : null;
    const cancelEls = root ? qsa("[data-hz-modal-cancel]", root) : [];

    if (!root || !titleEl || !okBtn) {
      return Promise.resolve(window.confirm(d ? `${t}\n\n${d}` : t));
    }

    return new Promise((resolve) => {
      const prev = document.activeElement instanceof HTMLElement ? document.activeElement : null;
      let finished = false;

      const cleanup = () => {
        document.removeEventListener("keydown", onKeyDown);
        okBtn.removeEventListener("click", onOk);
        for (const el of cancelEls) el.removeEventListener("click", onCancel);
      };

      const finish = (ok) => {
        if (finished) return;
        finished = true;
        cleanup();

        document.body.classList.remove("hz-modal-open");
        root.hidden = true;
        root.classList.add("hz-enter"); // reset for next open

        if (prev && typeof prev.focus === "function") {
          try {
            prev.focus();
          } catch {
            // ignore
          }
        }

        resolve(ok);
      };

      const onKeyDown = (evt) => {
        if (evt.key !== "Escape") return;
        evt.preventDefault();
        finish(false);
      };

      const onCancel = (evt) => {
        evt.preventDefault();
        finish(false);
      };

      const onOk = (evt) => {
        evt.preventDefault();
        finish(true);
      };

      titleEl.textContent = t;
      if (detailEl) {
        detailEl.textContent = d;
        detailEl.style.display = d ? "" : "none";
      }
      okBtn.textContent = (okText || tKey("modal.ok", "确认")).toString();

      for (const el of cancelEls) {
        if (el instanceof HTMLElement && el.hasAttribute("data-hz-modal-cancel")) {
          el.textContent = tKey("modal.cancel", "取消");
        }
      }

      root.hidden = false;
      root.classList.add("hz-enter");
      document.body.classList.add("hz-modal-open");
      void root.offsetHeight;
      root.classList.remove("hz-enter");

      document.addEventListener("keydown", onKeyDown);
      okBtn.addEventListener("click", onOk);
      for (const el of cancelEls) el.addEventListener("click", onCancel);

      if (typeof okBtn.focus === "function") {
        try {
          okBtn.focus();
        } catch {
          // ignore
        }
      }
    });
  };

  const onLinkClick = (e) => {
    if (e.defaultPrevented) return;
    if (e.button !== 0) return;
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;

    const a = e.target instanceof Element ? e.target.closest("a[href]") : null;
    if (!a) return;

    const href = (a.getAttribute("href") || "").trim();
    if (!href || href.startsWith("#")) return;

    const url = new URL(a.href, window.location.href);

    const confirmTitle = (a.getAttribute("data-confirm-download") || "").trim();
    if (confirmTitle) {
      const detail = (a.getAttribute("data-confirm-detail") || "").trim();
      e.preventDefault();
      confirmModal({ title: confirmTitle, detail, okText: tKey("modal.download", "下载") }).then((ok) => {
        if (!ok) return;
        window.location.href = url.href;
      });
      return;
    }

    if (shouldBypassPjax(url, a)) return;

    e.preventDefault();
    navigate(url);
  };

  const onPopState = () => {
    navigate(new URL(window.location.href), { replace: true, addHistory: false });
  };

  const onPreviewInput = (e) => {
    const t = e.target;
    if (!(t instanceof Element)) return;

    const name = (t.getAttribute("name") || "").trim();
    const id = (t.getAttribute("id") || "").trim();

    if (id === "gitPreviewPath" || name === "upstream" || name === "upstreamPath" || name === "upstreamHttps") {
      updateGitPreview();
      return;
    }

    if (
      id === "cdnjsPreviewPath" ||
      name === "assetUrl" ||
      name === "defaultGhUser" ||
      name === "defaultTTLSeconds" ||
      name === "ttlOverrides"
    ) {
      updateCdnjsPreview();
      return;
    }

    if (
      id === "torcherinoPreviewHost" ||
      id === "torcherinoPreviewPath" ||
      id === "hostMappingJson" ||
      name === "defaultTarget"
    ) {
      updateTorcherinoPreview();
      return;
    }
  };

  document.addEventListener("click", onFormatJsonClick);
  document.addEventListener("change", onTogglePassword);
  document.addEventListener("click", onLinkClick);
  document.addEventListener("input", onPreviewInput);
  document.addEventListener("change", onPreviewInput);
  window.addEventListener("popstate", onPopState);

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => refreshPage(), { once: true });
  } else {
    refreshPage();
  }

  window.HazukiUI = { qs, qsa, formatJson, navigate };
})();
