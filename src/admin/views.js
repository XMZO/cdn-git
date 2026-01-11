"use strict";

function escapeHtml(value) {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function renderLayout({ title, user, content, notice, error }) {
  const banner = error
    ? `<div class="banner banner-error">${escapeHtml(error)}</div>`
    : notice
      ? `<div class="banner banner-ok">${escapeHtml(notice)}</div>`
      : "";

  const appShell = user
    ? `
      <div class="app">
        <aside class="sidebar">
          <div class="brand">
            <div class="brand-title">Hazuki</div>
            <div class="brand-sub">Proxy Suite</div>
          </div>

          <div class="nav-section">
            <div class="nav-title">概览</div>
            <a class="nav-link" data-nav="/" href="/">概览</a>
            <a class="nav-link" data-nav="/wizard" href="/wizard">快速向导</a>
          </div>

          <div class="nav-section">
            <div class="nav-title">服务配置</div>
            <a class="nav-link" data-nav="/config/cdnjs" href="/config/cdnjs">jsDelivr 缓存（cdnjs）</a>
            <a class="nav-link" data-nav="/config/git" href="/config/git">GitHub Raw（git）</a>
            <a class="nav-link" data-nav="/config/torcherino" href="/config/torcherino">通用反代（torcherino）</a>
          </div>

          <div class="nav-section">
            <div class="nav-title">配置与备份</div>
            <a class="nav-link" data-nav="/config/versions" href="/config/versions">版本 & 回滚</a>
          </div>

          <div class="nav-section">
            <div class="nav-title">账号</div>
            <a class="nav-link" data-nav="/account" href="/account">修改密码</a>
          </div>

          <div class="sidebar-footer">
            <div class="me">
              <div class="me-name">${escapeHtml(user.username || "")}</div>
              <div class="me-sub">local admin</div>
            </div>
            <form method="post" action="/logout">
              <button class="btn btn-ghost" type="submit">退出登录</button>
            </form>
          </div>
        </aside>

        <main class="main">
          <div class="page">
            <div class="page-head">
              <div class="page-title">${escapeHtml(title || "")}</div>
              <div class="page-sub">配置保存在 SQLite，修改后即时生效（端口除外）。</div>
            </div>
            ${banner}
            ${content}
          </div>
        </main>
      </div>
    `
    : `
      <div class="public">
        <div class="public-card">
          <div class="public-title">${escapeHtml(title || "")}</div>
          ${banner}
          ${content}
        </div>
      </div>
    `;

  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(title)} - Hazuki</title>
  <style>
    :root {
      color-scheme: light dark;
      --bg: #0b0c10;
      --panel: rgba(255,255,255,.06);
      --panel-2: rgba(255,255,255,.08);
      --border: rgba(255,255,255,.12);
      --text: rgba(255,255,255,.92);
      --muted: rgba(255,255,255,.64);
      --accent: #6ee7ff;
      --good: #28a745;
      --bad: #dc3545;
      --shadow: 0 12px 30px rgba(0,0,0,.35);
      --radius: 14px;
    }
    @media (prefers-color-scheme: light) {
      :root {
        --bg: #f6f7fb;
        --panel: rgba(0,0,0,.04);
        --panel-2: rgba(0,0,0,.06);
        --border: rgba(0,0,0,.10);
        --text: rgba(0,0,0,.88);
        --muted: rgba(0,0,0,.56);
        --shadow: 0 10px 26px rgba(0,0,0,.10);
      }
    }

    * { box-sizing: border-box; }
    html, body { height: 100%; }
    body {
      margin: 0;
      background: radial-gradient(1200px 600px at 20% 0%, rgba(110,231,255,.12), transparent 55%),
                  radial-gradient(900px 500px at 90% 20%, rgba(167,139,250,.12), transparent 55%),
                  var(--bg);
      color: var(--text);
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial, "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif;
      line-height: 1.45;
    }
    a { color: inherit; text-decoration: none; }
    code {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
      font-size: 12px;
      padding: 2px 6px;
      border-radius: 8px;
      background: var(--panel);
      border: 1px solid var(--border);
    }

    .app { min-height: 100%; display: flex; }
    .sidebar {
      width: 260px;
      padding: 16px;
      border-right: 1px solid var(--border);
      background: rgba(0,0,0,.06);
      backdrop-filter: blur(10px);
    }
    @media (prefers-color-scheme: light) {
      .sidebar { background: rgba(255,255,255,.55); }
    }
    .brand { padding: 10px 10px 14px; border-radius: var(--radius); background: var(--panel); border: 1px solid var(--border); box-shadow: var(--shadow); }
    .brand-title { font-weight: 800; font-size: 18px; letter-spacing: .4px; }
    .brand-sub { font-size: 12px; color: var(--muted); margin-top: 2px; }

    .nav-section { margin-top: 14px; }
    .nav-title { font-size: 12px; color: var(--muted); padding: 6px 8px; }
    .nav-link {
      display: block;
      padding: 9px 10px;
      border-radius: 12px;
      border: 1px solid transparent;
    }
    .nav-link:hover { background: var(--panel); border-color: var(--border); }
    .nav-link.active { background: var(--panel-2); border-color: rgba(110,231,255,.35); box-shadow: 0 0 0 2px rgba(110,231,255,.12) inset; }

    .sidebar-footer { margin-top: 18px; padding-top: 12px; border-top: 1px solid var(--border); display: flex; gap: 10px; align-items: center; justify-content: space-between; }
    .me-name { font-weight: 700; }
    .me-sub { font-size: 12px; color: var(--muted); }

    .main { flex: 1; padding: 22px; }
    .page { max-width: 980px; margin: 0 auto; }
    .page-head { margin-bottom: 14px; }
    .page-title { font-size: 20px; font-weight: 800; }
    .page-sub { color: var(--muted); font-size: 13px; margin-top: 6px; }

    .banner { padding: 12px 12px; border-radius: var(--radius); border: 1px solid var(--border); background: var(--panel); box-shadow: var(--shadow); margin: 12px 0 16px; }
    .banner-ok { border-color: rgba(40,167,69,.35); background: rgba(40,167,69,.10); }
    .banner-error { border-color: rgba(220,53,69,.35); background: rgba(220,53,69,.10); }

    .card { border: 1px solid var(--border); background: var(--panel); border-radius: var(--radius); padding: 14px; box-shadow: var(--shadow); margin: 12px 0; }
    .card-title { font-weight: 800; margin: 0 0 6px; }
    .card-sub { color: var(--muted); font-size: 13px; margin: 0 0 10px; }

    .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
    @media (max-width: 860px) {
      .grid-2 { grid-template-columns: 1fr; }
      .app { flex-direction: column; }
      .sidebar { width: 100%; border-right: none; border-bottom: 1px solid var(--border); }
      .main { padding: 16px; }
    }

    .row { margin: 10px 0; }
    .label { font-weight: 700; margin-bottom: 6px; display: flex; gap: 8px; align-items: center; }
    .label small { font-weight: 600; color: var(--muted); }
    input[type=text], input[type=password], input[type=number], textarea, select {
      width: 100%;
      padding: 10px 12px;
      border-radius: 12px;
      border: 1px solid var(--border);
      background: rgba(0,0,0,.08);
      color: var(--text);
      outline: none;
    }
    @media (prefers-color-scheme: light) {
      input[type=text], input[type=password], input[type=number], textarea, select { background: rgba(255,255,255,.8); }
    }
    textarea { min-height: 130px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace; }
    textarea.invalid { border-color: rgba(220,53,69,.55); box-shadow: 0 0 0 2px rgba(220,53,69,.15); }
    .hint { color: var(--muted); font-size: 12px; margin-top: 6px; display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
    .hint .spacer { flex: 1; }
    .hint .json-msg.ok { color: rgba(40,167,69,.95); }
    .hint .json-msg.bad { color: rgba(220,53,69,.95); }

    details { border: 1px dashed var(--border); border-radius: var(--radius); padding: 10px 12px; margin: 12px 0; background: rgba(0,0,0,.03); }
    details > summary { cursor: pointer; font-weight: 800; }
    details > summary small { color: var(--muted); font-weight: 600; margin-left: 8px; }

    .btn { padding: 9px 12px; border-radius: 12px; border: 1px solid var(--border); background: var(--panel-2); color: var(--text); cursor: pointer; font-weight: 700; }
    .btn:hover { filter: brightness(1.08); }
    .btn-primary { border-color: rgba(110,231,255,.35); background: rgba(110,231,255,.14); }
    .btn-danger { border-color: rgba(220,53,69,.35); background: rgba(220,53,69,.12); }
    .btn-ghost { background: transparent; }
    .btn-row { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; margin-top: 12px; }

    table { width: 100%; border-collapse: collapse; border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; }
    th, td { padding: 10px 10px; border-bottom: 1px solid var(--border); text-align: left; font-size: 13px; }
    th { color: var(--muted); font-weight: 700; background: rgba(0,0,0,.05); }

    .public { min-height: 100%; display: grid; place-items: center; padding: 24px; }
    .public-card { width: 100%; max-width: 520px; border: 1px solid var(--border); background: var(--panel); border-radius: var(--radius); padding: 18px; box-shadow: var(--shadow); }
    .public-title { font-size: 20px; font-weight: 900; margin-bottom: 10px; }
  </style>
</head>
<body>
  ${appShell}
  <script>
    (function () {
      // Active nav
      var path = window.location.pathname || '/';
      var links = document.querySelectorAll('a[data-nav]');
      for (var i = 0; i < links.length; i++) {
        var a = links[i];
        var base = a.getAttribute('data-nav');
        if (!base) continue;
        if (base === '/' ? path === '/' : (path === base || path.indexOf(base + '/') === 0)) {
          a.classList.add('active');
        }
      }

      // JSON validation + formatter
      function validateJsonTextarea(t) {
        var msg = t.closest('.row') ? t.closest('.row').querySelector('.json-msg') : null;
        var raw = t.value.trim();
        if (!raw) {
          t.classList.remove('invalid');
          if (msg) { msg.textContent = ''; msg.className = 'json-msg'; }
          return true;
        }
        try {
          JSON.parse(raw);
          t.classList.remove('invalid');
          if (msg) { msg.textContent = 'JSON OK'; msg.className = 'json-msg ok'; }
          return true;
        } catch (e) {
          t.classList.add('invalid');
          if (msg) { msg.textContent = 'JSON 错误：' + (e && e.message ? e.message : 'invalid'); msg.className = 'json-msg bad'; }
          return false;
        }
      }

      var jsonAreas = document.querySelectorAll('textarea[data-json]');
      for (var j = 0; j < jsonAreas.length; j++) {
        (function (t) {
          validateJsonTextarea(t);
          t.addEventListener('input', function () { validateJsonTextarea(t); });
        })(jsonAreas[j]);
      }

      var formatButtons = document.querySelectorAll('button[data-format-json]');
      for (var k = 0; k < formatButtons.length; k++) {
        (function (btn) {
          btn.addEventListener('click', function () {
            var row = btn.closest('.row');
            if (!row) return;
            var t = row.querySelector('textarea[data-json]');
            if (!t) return;
            try {
              var obj = JSON.parse(t.value);
              t.value = JSON.stringify(obj, null, 2);
              validateJsonTextarea(t);
            } catch (e) {
              validateJsonTextarea(t);
              t.focus();
            }
          });
        })(formatButtons[k]);
      }

      document.addEventListener('submit', function (ev) {
        var form = ev.target;
        if (!form || !form.querySelector) return;
        var bad = form.querySelector('textarea.invalid');
        if (bad) {
          ev.preventDefault();
          bad.focus();
          alert('有 JSON 字段格式不正确，请先修正。');
        }
      }, true);

      // Fill HOST templates
      var host = window.location.hostname || 'localhost';
      var fill = document.querySelectorAll('[data-fill-host]');
      for (var z = 0; z < fill.length; z++) {
        var el = fill[z];
        var tpl = el.getAttribute('data-fill-host');
        if (!tpl) continue;
        el.textContent = tpl.split('HOST').join(host);
      }
    })();
  </script>
</body>
</html>`;
}

function renderLoginPage({ error }) {
  const content = `
    <div class="card-sub">请输入本地管理员账号登录。</div>
    <form method="post" action="/login">
      <div class="row">
        <div class="label">用户名</div>
        <input type="text" name="username" autocomplete="username" placeholder="admin" required />
      </div>
      <div class="row">
        <div class="label">密码</div>
        <input type="password" name="password" autocomplete="current-password" required />
      </div>
      <div class="btn-row">
        <button class="btn btn-primary" type="submit">登录</button>
      </div>
    </form>
  `;
  return renderLayout({ title: "登录", user: null, content, error });
}

function renderSetupPage({ error }) {
  const content = `
    <div class="card-sub">首次启动未检测到管理员账号，请先创建本地管理员。</div>
    <form method="post" action="/setup">
      <div class="row">
        <div class="label">管理员用户名 <small>（HAZUKI_ADMIN_USERNAME）</small></div>
        <input type="text" name="username" autocomplete="username" placeholder="admin" required />
      </div>
      <div class="row">
        <div class="label">管理员密码 <small>（HAZUKI_ADMIN_PASSWORD）</small></div>
        <input type="password" name="password" autocomplete="new-password" required />
        <div class="hint">至少 8 位。</div>
      </div>
      <div class="btn-row">
        <button class="btn btn-primary" type="submit">创建并登录</button>
      </div>
    </form>
  `;
  return renderLayout({ title: "初始化", user: null, content, error });
}

function renderDashboard({ updatedAt, ports, warnings }) {
  const warningCards = (warnings || [])
    .map((w) => `<div class="banner banner-error">${escapeHtml(w)}</div>`)
    .join("");

  const content = `
    ${warningCards}

    <div class="card">
      <div class="card-title">服务端口</div>
      <div class="card-sub">多端口模式：三类代理各自端口，面板独立端口。</div>
      <div class="grid-2">
        <div>
          <div class="row"><div class="label">面板</div><code>http://&lt;host&gt;:${escapeHtml(ports.admin)}</code></div>
          <div class="row"><div class="label">torcherino</div><code>http://&lt;host&gt;:${escapeHtml(ports.torcherino)}</code></div>
        </div>
        <div>
          <div class="row"><div class="label">cdnjs</div><code>http://&lt;host&gt;:${escapeHtml(ports.cdnjs)}</code></div>
          <div class="row"><div class="label">git</div><code>http://&lt;host&gt;:${escapeHtml(ports.git)}</code></div>
        </div>
      </div>
      <div class="hint">配置更新时间：<code>${escapeHtml(updatedAt || "")}</code></div>
    </div>

    <div class="card">
      <div class="card-title">快速入口</div>
      <div class="card-sub">先把三项服务的“基础配置”填好，再按需打开高级选项。</div>
      <div class="btn-row">
        <a class="btn btn-primary" href="/config/cdnjs">配置 jsDelivr 缓存</a>
        <a class="btn btn-primary" href="/config/git">配置 GitHub Raw</a>
        <a class="btn btn-primary" href="/config/torcherino">配置 通用反代</a>
        <a class="btn" href="/config/versions">版本 & 备份</a>
      </div>
    </div>

    <div class="card">
      <div class="card-title">快速说明</div>
      <div class="card-sub">常见访问方式示例（把 &lt;host&gt; 换成你的域名/IP）。</div>
      <div class="row"><div class="label">cdnjs</div><div class="hint"><code>/${"gh"}/&lt;user&gt;/&lt;path&gt;</code> 或 <code>/&lt;path&gt;</code>（走 DEFAULT_GH_USER）</div></div>
      <div class="row"><div class="label">git</div><div class="hint"><code>/&lt;file&gt;</code> → 自动拼接 <code>UPSTREAM_PATH</code></div></div>
      <div class="row"><div class="label">torcherino</div><div class="hint">按 Host 映射到上游（HOST_MAPPING）或走 DEFAULT_TARGET</div></div>
    </div>
  `;

  return content;
}

function renderAccountPage() {
  return `
    <div class="card">
      <div class="card-title">修改密码</div>
      <div class="card-sub">仅影响本地管理员登录，不影响代理服务对外行为。</div>
      <form method="post" action="/account/password">
        <div class="row">
          <div class="label">新密码</div>
          <input type="password" name="newPassword" autocomplete="new-password" required />
          <div class="hint">至少 8 位。</div>
        </div>
        <div class="btn-row">
          <button class="btn btn-primary" type="submit">保存</button>
        </div>
      </form>
    </div>
  `;
}

function renderCdnjsForm({ config }) {
  const allowed = (config.cdnjs.allowedGhUsers || []).join(", ");
  return `
    <div class="card">
      <div class="card-title">服务说明</div>
      <div class="card-sub">代理 jsDelivr 的 GitHub 资源（<code>/gh/*</code>），并用 Redis 缓存二进制内容。</div>
      <div class="hint">
        <span>示例：</span>
        <code>http://&lt;host&gt;:3001/gh/XMZO/pic/main/a.png</code>
        <span class="spacer"></span>
        <span>老环境变量：<code>ASSET_URL</code>、<code>ALLOWED_GH_USERS</code>、<code>DEFAULT_GH_USER</code>、<code>REDIS_HOST</code>、<code>REDIS_PORT</code></span>
      </div>
    </div>

    <form method="post" action="/config/cdnjs">
      <div class="card">
        <div class="card-title">基础配置</div>
        <div class="row">
          <div class="label">jsDelivr 源站 <small>（ASSET_URL）</small></div>
          <input type="text" name="assetUrl" value="${escapeHtml(config.cdnjs.assetUrl)}" placeholder="https://cdn.jsdelivr.net" required />
          <div class="hint">通常不需要改，除非你有自建镜像源。</div>
        </div>
        <div class="row">
          <div class="label">默认 GitHub 用户 <small>（DEFAULT_GH_USER）</small></div>
          <input type="text" name="defaultGhUser" value="${escapeHtml(config.cdnjs.defaultGhUser)}" placeholder="XMZO" />
          <div class="hint">用于短路径：访问 <code>/&lt;path&gt;</code> 会自动拼成 <code>/gh/&lt;DEFAULT_GH_USER&gt;/&lt;path&gt;</code>。</div>
        </div>
        <div class="row">
          <div class="label">允许的 GitHub 用户 <small>（ALLOWED_GH_USERS）</small></div>
          <input type="text" name="allowedGhUsers" value="${escapeHtml(allowed)}" placeholder="XMZO,starsei" />
          <div class="hint">逗号分隔；为空会导致 <code>/gh/*</code> 全部拒绝（403）。</div>
        </div>
      </div>

      <details>
        <summary>高级选项 <small>Redis 缓存</small></summary>
        <div class="row">
          <div class="label">Redis Host <small>（REDIS_HOST）</small></div>
          <input type="text" name="redisHost" value="${escapeHtml(config.cdnjs.redis.host)}" placeholder="redis" required />
        </div>
        <div class="row">
          <div class="label">Redis Port <small>（REDIS_PORT）</small></div>
          <input type="number" name="redisPort" value="${escapeHtml(config.cdnjs.redis.port)}" min="1" max="65535" required />
          <div class="hint">Redis 不可用时仍可代理，但会变成无缓存（MISS）。</div>
        </div>
      </details>

      <div class="btn-row">
        <button class="btn btn-primary" type="submit">保存</button>
      </div>
    </form>
  `;
}

function renderGitForm({ config, tokenIsSet }) {
  return `
    <div class="card">
      <div class="card-title">服务说明</div>
      <div class="card-sub">代理 <code>raw.githubusercontent.com</code>，支持私有仓库 Token、CORS、缓存策略、HTML 内容替换。</div>
      <div class="hint">
        <span>示例：</span>
        <code>http://&lt;host&gt;:3002/a.png</code>
        <span class="spacer"></span>
        <span>老环境变量：<code>GITHUB_TOKEN</code>、<code>UPSTREAM_PATH</code>、<code>CORS_*</code>、<code>CACHE_CONTROL*</code>、<code>REPLACE_DICT</code></span>
      </div>
    </div>

    <form method="post" action="/config/git">
      <div class="card">
        <div class="card-title">基础配置</div>
        <div class="row">
          <div class="label">默认仓库路径 <small>（UPSTREAM_PATH）</small></div>
          <input type="text" name="upstreamPath" value="${escapeHtml(config.git.upstreamPath)}" placeholder="/XMZO/pic/main" required />
          <div class="hint">请求 <code>/x.png</code> 会拼成 <code>UPSTREAM_PATH + /x.png</code>。</div>
        </div>
        <div class="grid-2">
          <div class="row">
            <div class="label">上游域名（桌面） <small>（UPSTREAM）</small></div>
            <input type="text" name="upstream" value="${escapeHtml(config.git.upstream)}" placeholder="raw.githubusercontent.com" required />
          </div>
          <div class="row">
            <div class="label">上游域名（移动） <small>（UPSTREAM_MOBILE）</small></div>
            <input type="text" name="upstreamMobile" value="${escapeHtml(config.git.upstreamMobile)}" placeholder="raw.githubusercontent.com" required />
          </div>
        </div>
        <div class="grid-2">
          <div class="row">
            <div class="label">上游协议 <small>（UPSTREAM_HTTPS）</small></div>
            <select name="https">
              <option value="true" ${config.git.https ? "selected" : ""}>https</option>
              <option value="false" ${!config.git.https ? "selected" : ""}>http</option>
            </select>
          </div>
          <div class="row">
            <div class="label">鉴权 Scheme <small>（GITHUB_AUTH_SCHEME）</small></div>
            <select name="githubAuthScheme">
              <option value="token" ${config.git.githubAuthScheme === "token" ? "selected" : ""}>token（classic PAT）</option>
              <option value="Bearer" ${config.git.githubAuthScheme === "Bearer" ? "selected" : ""}>Bearer（fine-grained）</option>
            </select>
          </div>
        </div>
        <div class="row">
          <div class="label">GitHub Token <small>（GITHUB_TOKEN）</small></div>
          <input type="password" name="githubToken" value="" placeholder="${tokenIsSet ? "已设置（留空不变）" : "未设置"}" />
          <div class="hint">
            <span>用于私有仓库/提高限额。</span>
            <span class="spacer"></span>
            <label style="display:flex; gap:8px; align-items:center; font-weight:700;">
              <input type="checkbox" name="clearGithubToken" />
              清空 Token
            </label>
          </div>
        </div>
      </div>

      <details>
        <summary>缓存策略 <small>（Cache-Control）</small></summary>
        <div class="grid-2">
          <div class="row">
            <div class="label">禁用缓存 <small>（DISABLE_CACHE）</small></div>
            <select name="disableCache">
              <option value="false" ${!config.git.disableCache ? "selected" : ""}>否（按规则缓存）</option>
              <option value="true" ${config.git.disableCache ? "selected" : ""}>是（no-store）</option>
            </select>
          </div>
          <div class="row">
            <div class="label">全局 Cache-Control <small>（CACHE_CONTROL）</small></div>
            <input type="text" name="cacheControl" value="${escapeHtml(config.git.cacheControl)}" placeholder="留空则按内容类型使用下面默认值" />
          </div>
        </div>
        <div class="grid-2">
          <div class="row">
            <div class="label">媒体默认值 <small>（CACHE_CONTROL_MEDIA）</small></div>
            <input type="text" name="cacheControlMedia" value="${escapeHtml(config.git.cacheControlMedia)}" placeholder="public, max-age=43200000" />
          </div>
          <div class="row">
            <div class="label">文本默认值 <small>（CACHE_CONTROL_TEXT）</small></div>
            <input type="text" name="cacheControlText" value="${escapeHtml(config.git.cacheControlText)}" placeholder="public, max-age=60" />
          </div>
        </div>
      </details>

      <details>
        <summary>访问控制 <small>（地区/IP）</small></summary>
        <div class="grid-2">
          <div class="row">
            <div class="label">屏蔽地区 <small>（BLOCKED_REGION）</small></div>
            <input type="text" name="blockedRegions" value="${escapeHtml((config.git.blockedRegions || []).join(", "))}" placeholder="CN,HK" />
            <div class="hint">依赖请求头 <code>cf-ipcountry</code>（通常来自 Cloudflare）。</div>
          </div>
          <div class="row">
            <div class="label">屏蔽 IP <small>（BLOCKED_IP_ADDRESS）</small></div>
            <input type="text" name="blockedIpAddresses" value="${escapeHtml((config.git.blockedIpAddresses || []).join(", "))}" placeholder="0.0.0.0,127.0.0.1" />
            <div class="hint">留空表示不阻止任何 IP。</div>
          </div>
        </div>
      </details>

      <details>
        <summary>CORS <small>（跨域访问）</small></summary>
        <div class="grid-2">
          <div class="row">
            <div class="label">允许来源 <small>（CORS_ORIGIN）</small></div>
            <input type="text" name="corsOrigin" value="${escapeHtml(config.git.corsOrigin)}" placeholder="*" />
            <div class="hint">支持 <code>*</code> 或逗号分隔 allowlist，例如 <code>https://a.com,https://b.com</code>。</div>
          </div>
          <div class="row">
            <div class="label">允许携带凭证 <small>（CORS_ALLOW_CREDENTIALS）</small></div>
            <select name="corsAllowCredentials">
              <option value="false" ${!config.git.corsAllowCredentials ? "selected" : ""}>false</option>
              <option value="true" ${config.git.corsAllowCredentials ? "selected" : ""}>true</option>
            </select>
            <div class="hint">当 <code>CORS_ORIGIN=*</code> 时不能开启。</div>
          </div>
        </div>
        <div class="row">
          <div class="label">暴露响应头 <small>（CORS_EXPOSE_HEADERS）</small></div>
          <input type="text" name="corsExposeHeaders" value="${escapeHtml(config.git.corsExposeHeaders)}" />
        </div>
      </details>

      <details>
        <summary>HTML 替换 <small>（REPLACE_DICT）</small></summary>
        <div class="row">
          <div class="label">替换字典 <small>JSON</small></div>
          <textarea name="replaceDict" data-json>${escapeHtml(
            JSON.stringify(config.git.replaceDict || {}, null, 2)
          )}</textarea>
          <div class="hint">
            <span>占位符：<code>$upstream</code>、<code>$custom_domain</code>（用于把上游域名替换为当前域名）。</span>
            <span class="spacer"></span>
            <button class="btn btn-ghost" type="button" data-format-json>格式化 JSON</button>
            <span class="json-msg" aria-live="polite"></span>
          </div>
        </div>
      </details>

      <div class="btn-row">
        <button class="btn btn-primary" type="submit">保存</button>
      </div>
    </form>
  `;
}

function renderTorcherinoForm({ config, secretIsSet }) {
  return `
    <div class="card">
      <div class="card-title">服务说明</div>
      <div class="card-sub">通用反向代理：按 Host 映射到上游，并会重写 JSON/HTML/重定向中的 <code>.pages.dev</code>/<code>.hf.space</code> 为当前域名。</div>
      <div class="hint">
        <span>示例：</span>
        <code>DEFAULT_TARGET=your-project.pages.dev</code>
        <span class="spacer"></span>
        <span>老环境变量：<code>DEFAULT_TARGET</code>、<code>HOST_MAPPING</code>、<code>WORKER_SECRET_KEY</code></span>
      </div>
    </div>

    <form method="post" action="/config/torcherino">
      <div class="card">
        <div class="card-title">基础配置</div>
        <div class="row">
          <div class="label">默认上游 <small>（DEFAULT_TARGET）</small></div>
          <input type="text" name="defaultTarget" value="${escapeHtml(config.torcherino.defaultTarget)}" placeholder="your-project.pages.dev 或 your-space.hf.space" />
          <div class="hint">当 <code>HOST_MAPPING</code> 未命中时使用；若你只用映射也可以留空。</div>
        </div>
        <div class="row">
          <div class="label">域名映射 <small>（HOST_MAPPING）</small></div>
          <textarea name="hostMapping" data-json>${escapeHtml(
            JSON.stringify(config.torcherino.hostMapping || {}, null, 2)
          )}</textarea>
          <div class="hint">
            <span>示例：<code>{"img.example.com":"xxx.pages.dev","api.example.com":"yyy.hf.space"}</code></span>
            <span class="spacer"></span>
            <button class="btn btn-ghost" type="button" data-format-json>格式化 JSON</button>
            <span class="json-msg" aria-live="polite"></span>
          </div>
        </div>
        <div class="row">
          <div class="label">转发验证密钥 <small>（WORKER_SECRET_KEY）</small></div>
          <input type="password" name="workerSecretKey" value="" placeholder="${secretIsSet ? "已设置（留空不变）" : "未设置"}" />
          <div class="hint">
            <span>可选：会以 <code>x-forwarded-by-worker</code> 头转发到上游。</span>
            <span class="spacer"></span>
            <label style="display:flex; gap:8px; align-items:center; font-weight:700;">
              <input type="checkbox" name="clearWorkerSecretKey" />
              清空密钥
            </label>
          </div>
        </div>
      </div>

      <div class="btn-row">
        <button class="btn btn-primary" type="submit">保存</button>
      </div>
    </form>
  `;
}

function renderVersionsPage({ versions }) {
  const rows = (versions || [])
    .map((v) => {
      return `<tr>
        <td><code>${escapeHtml(v.id)}</code></td>
        <td><code>${escapeHtml(v.created_at)}</code></td>
        <td>${escapeHtml(v.note || "")}</td>
        <td>
          <form method="post" action="/config/versions/${escapeHtml(v.id)}/restore" onsubmit="return confirm('确定回滚到该版本？')">
            <button class="btn btn-danger" type="submit">回滚</button>
          </form>
        </td>
      </tr>`;
    })
    .join("");

  return `
    <div class="card">
      <div class="card-title">备份</div>
      <div class="card-sub">导出的 JSON 是“加密后的配置”（包含 <code>enc:v1:...</code> 字段）。请妥善保管并确保服务器启动时提供同一 <code>HAZUKI_MASTER_KEY</code>。</div>
      <div class="btn-row">
        <a class="btn btn-primary" href="/config/export">下载备份</a>
        <a class="btn" href="/config/import">导入备份</a>
      </div>
    </div>

    <div class="card">
      <div class="card-title">配置版本</div>
      <div class="card-sub">每次保存都会生成新版本；可随时回滚。</div>
      <table>
        <thead><tr><th>ID</th><th>Created At</th><th>Note</th><th>Action</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  `;
}

function renderImportPage() {
  return `
    <div class="card">
      <div class="card-title">导入备份</div>
      <div class="card-sub">粘贴从“下载备份”导出的 JSON。导入会写入一个新版本。</div>
      <form method="post" action="/config/import">
        <div class="row">
          <div class="label">config.json</div>
          <textarea name="configJson" data-json placeholder="{ ... }" required></textarea>
          <div class="hint">
            <button class="btn btn-ghost" type="button" data-format-json>格式化 JSON</button>
            <span class="json-msg" aria-live="polite"></span>
          </div>
        </div>
        <div class="btn-row">
          <button class="btn btn-primary" type="submit">导入</button>
        </div>
      </form>
    </div>
  `;
}

function renderWizardPage({ form, tokenIsSet, secretIsSet }) {
  return `
    <div class="card">
      <div class="card-title">3 分钟快速配置</div>
      <div class="card-sub">只填“最少必要项”。更细的缓存/CORS/替换规则等请去对应服务页的高级选项。</div>
      <div class="hint">
        <span>自检：</span>
        <code data-fill-host="http://HOST:3000/_hazuki/health"></code>
        <code data-fill-host="http://HOST:3001/_hazuki/health"></code>
        <code data-fill-host="http://HOST:3002/_hazuki/health"></code>
      </div>
    </div>

    <form method="post" action="/wizard">
      <div class="card">
        <div class="card-title">Step 1：通用反代（torcherino）</div>
        <div class="card-sub">至少填一个：DEFAULT_TARGET 或 HOST_MAPPING。</div>

        <div class="row">
          <div class="label">默认上游 <small>（DEFAULT_TARGET）</small></div>
          <input type="text" name="torcherinoDefaultTarget" value="${escapeHtml(form.torcherinoDefaultTarget)}" placeholder="your-project.pages.dev 或 your-space.hf.space" />
          <div class="hint">只反代一个站点就填它；多站点建议用下面的映射。</div>
        </div>

        <div class="row">
          <div class="label">域名映射 <small>（HOST_MAPPING）</small></div>
          <textarea name="torcherinoHostMappingJson" data-json>${escapeHtml(form.torcherinoHostMappingJson)}</textarea>
          <div class="hint">
            <span>示例：<code>{"img.example.com":"xxx.pages.dev"}</code></span>
            <span class="spacer"></span>
            <button class="btn btn-ghost" type="button" data-format-json>格式化 JSON</button>
            <span class="json-msg" aria-live="polite"></span>
          </div>
        </div>

        <details>
          <summary>可选：转发验证 <small>WORKER_SECRET_KEY</small></summary>
          <div class="row">
            <div class="label">转发验证密钥 <small>（WORKER_SECRET_KEY）</small></div>
            <input type="password" name="torcherinoWorkerSecretKey" value="" placeholder="${secretIsSet ? "已设置（留空不变）" : "未设置"}" />
            <div class="hint">
              <span>会以 <code>x-forwarded-by-worker</code> 头转发给上游。</span>
              <span class="spacer"></span>
              <label style="display:flex; gap:8px; align-items:center; font-weight:700;">
                <input type="checkbox" name="torcherinoClearWorkerSecretKey" />
                清空密钥
              </label>
            </div>
          </div>
        </details>
      </div>

      <div class="card">
        <div class="card-title">Step 2：jsDelivr 缓存（cdnjs）</div>
        <div class="card-sub">用于代理 <code>/gh/&lt;user&gt;/&lt;path&gt;</code>，并使用 Redis 缓存。</div>

        <div class="grid-2">
          <div class="row">
            <div class="label">默认 GitHub 用户 <small>（DEFAULT_GH_USER）</small></div>
            <input type="text" name="cdnjsDefaultGhUser" value="${escapeHtml(form.cdnjsDefaultGhUser)}" placeholder="XMZO" />
            <div class="hint">用于短路径：<code>/&lt;path&gt;</code>。</div>
          </div>
          <div class="row">
            <div class="label">允许用户 <small>（ALLOWED_GH_USERS）</small></div>
            <input type="text" name="cdnjsAllowedGhUsers" value="${escapeHtml(form.cdnjsAllowedGhUsers)}" placeholder="XMZO,starsei" />
            <div class="hint">为空会导致 <code>/gh/*</code> 全部拒绝。</div>
          </div>
        </div>

        <details>
          <summary>可选：源站与缓存 <small>ASSET_URL / REDIS</small></summary>
          <div class="row">
            <div class="label">jsDelivr 源站 <small>（ASSET_URL）</small></div>
            <input type="text" name="cdnjsAssetUrl" value="${escapeHtml(form.cdnjsAssetUrl)}" placeholder="https://cdn.jsdelivr.net" />
          </div>
          <div class="grid-2">
            <div class="row">
              <div class="label">Redis Host <small>（REDIS_HOST）</small></div>
              <input type="text" name="cdnjsRedisHost" value="${escapeHtml(form.cdnjsRedisHost)}" placeholder="redis" />
            </div>
            <div class="row">
              <div class="label">Redis Port <small>（REDIS_PORT）</small></div>
              <input type="number" name="cdnjsRedisPort" value="${escapeHtml(form.cdnjsRedisPort)}" min="1" max="65535" />
            </div>
          </div>
        </details>
      </div>

      <div class="card">
        <div class="card-title">Step 3：GitHub Raw（git）</div>
        <div class="card-sub">主要填 <code>UPSTREAM_PATH</code>；Token 仅私有仓库需要。</div>

        <div class="row">
          <div class="label">默认仓库路径 <small>（UPSTREAM_PATH）</small></div>
          <input type="text" name="gitUpstreamPath" value="${escapeHtml(form.gitUpstreamPath)}" placeholder="/XMZO/pic/main" required />
          <div class="hint">访问 <code>/a.png</code> 会代理成 <code>UPSTREAM_PATH + /a.png</code>。</div>
        </div>

        <details>
          <summary>可选：私有仓库 Token <small>GITHUB_TOKEN</small></summary>
          <div class="row">
            <div class="label">GitHub Token <small>（GITHUB_TOKEN）</small></div>
            <input type="password" name="gitGithubToken" value="" placeholder="${tokenIsSet ? "已设置（留空不变）" : "未设置"}" />
            <div class="hint">
              <span class="spacer"></span>
              <label style="display:flex; gap:8px; align-items:center; font-weight:700;">
                <input type="checkbox" name="gitClearGithubToken" />
                清空 Token
              </label>
            </div>
          </div>
        </details>
      </div>

      <div class="btn-row">
        <button class="btn btn-primary" type="submit">一键保存</button>
        <a class="btn" href="/">返回概览</a>
      </div>
    </form>
  `;
}

module.exports = {
  escapeHtml,
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
};
