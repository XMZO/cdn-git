# Hazuki Proxy Suite

把 `cdnjs`、`git`、`torcherino` 三个代理服务合并为一个大项目：同一进程多端口运行 + SQLite 配置中心 + Web 面板。

## 项目结构

```
├── cdnjs/        # jsDelivr CDN 缓存代理（独立版本）
├── git/          # GitHub Raw 文件代理（独立版本）
├── torcherino/   # 通用反向代理（独立版本）
└── src/          # Hazuki 主进程
```

## 端口（默认）

- `3100`：Web 面板（本地管理员登录）
- `3000`：torcherino（通用反代）
- `3001`：cdnjs（jsDelivr `/gh/*` 缓存代理，Redis 缓存）
- `3002`：git（`raw.githubusercontent.com` 代理，支持私有仓库 Token/CORS/替换规则）

端口可在 Web 面板里修改；使用 Docker 时如需改端口，记得同步调整 `docker-compose.yml` 的端口映射。

## 快速部署（Docker）

```bash
cp .env.example .env
nano .env
docker compose up -d --build
```

启动后：打开 `http://你的服务器:3100` 登录并配置（推荐先用“快速向导”）。

## 本地启动（不使用 Docker）

```bash
cp .env.example .env
npm install
npm start
```

## 管理员账号（用户名/密码）

- 没有内置默认账号：第一次访问面板会跳转到 `http://你的服务器:3100/setup` 创建管理员
- 或者在 `.env` 里提前设置 `HAZUKI_ADMIN_USERNAME` / `HAZUKI_ADMIN_PASSWORD`，首次启动会自动创建（仅第一次）

## 服务说明

### cdnjs - jsDelivr CDN 缓存

代理 jsDelivr CDN，使用 Redis 缓存静态资源。

| 配置项 | 说明 |
|--------|------|
| 端口 | 3001 |
| ASSET_URL | 上游 CDN（默认 `https://cdn.jsdelivr.net`） |
| ALLOWED_GH_USERS | 允许代理的 GitHub 用户（逗号分隔） |
| DEFAULT_GH_USER | 默认用户（简短路径使用） |
| REDIS_HOST / REDIS_PORT | Redis 地址 |

访问方式：
- `/gh/用户名/文件路径` - 指定用户
- `/文件路径` - 使用默认用户

### git - GitHub Raw 代理

代理 `raw.githubusercontent.com`，支持 Token 认证访问私有仓库。

| 配置项 | 说明 |
|--------|------|
| 端口 | 3002 |
| GITHUB_TOKEN | GitHub Personal Access Token |
| GITHUB_AUTH_SCHEME | `token` 或 `Bearer` |
| UPSTREAM | 上游域名（默认 `raw.githubusercontent.com`） |
| UPSTREAM_PATH | 默认仓库路径（如 `/用户名/仓库/分支`） |

访问方式：
- `/文件路径` - 自动拼接 UPSTREAM_PATH

其他配置（CORS、缓存策略、替换规则、地区/IP 封禁等）见 `.env.example` 或 Web 面板的 git 配置页。

### torcherino - 通用反向代理

通用反代服务，可代理 Cloudflare Pages、Hugging Face Space 等。

| 配置项 | 说明 |
|--------|------|
| 端口 | 3000 |
| DEFAULT_TARGET | 默认后端域名 |
| HOST_MAPPING | 多域名映射（JSON 格式） |
| WORKER_SECRET_KEY | 验证密钥 |
| WORKER_SECRET_HEADERS | 转发到上游的 Header 名称（逗号分隔，默认 `x-forwarded-by-worker`） |
| WORKER_SECRET_HEADER_MAP | 转发到上游的 Header->值（JSON 对象，会覆盖同名 Header 的 WORKER_SECRET_KEY 设置） |

## 健康检查

- torcherino：`http://HOST:3000/_hazuki/health`
- cdnjs：`http://HOST:3001/_hazuki/health`
- git：`http://HOST:3002/_hazuki/health`

## 独立启动某个服务（可选）

如果只需要单一服务，可进入子目录使用其独立 docker-compose：

```bash
cd cdnjs && docker compose up -d     # jsDelivr 缓存
cd git && docker compose up -d       # GitHub 代理
cd torcherino && docker compose up -d # 通用反代
```

## 配置与备份

- 配置存储：SQLite（Docker 默认 `/data/hazuki.db`，可用 `HAZUKI_DB_PATH` 指定）
- Web 面板支持：编辑三模块配置、配置版本回滚、导入/导出备份
- 首次启动会用 `.env` 里的变量做一次 seed；之后以 SQLite 为准（完整列表见 `.env.example`）
- 若数据库里存在加密的敏感配置（形如 `enc:v1:...`），启动时必须提供同一个 `HAZUKI_MASTER_KEY`，否则会直接退出

## Nginx 反代示例

```nginx
server {
    listen 443 ssl;
    server_name cdn.example.com;

    location / {
        proxy_pass http://127.0.0.1:3001;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## License

MIT
