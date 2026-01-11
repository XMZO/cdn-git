# Hazuki Proxy Suite

把 `cdnjs`、`git`、`torcherino` 三个代理服务合并为一个大项目：同一进程多端口运行 + SQLite 配置中心 + Web 面板。

## 项目结构

```
├── cdnjs/        # jsDelivr CDN 缓存代理（独立版本）
├── git/          # GitHub Raw 文件代理（独立版本）
├── torcherino/   # 通用反向代理（独立版本）
└── src/          # Hazuki 主进程
```

## 端口

- `3100`：Web 面板（本地管理员登录）
- `3000`：torcherino（通用反代）
- `3001`：cdnjs（jsDelivr `/gh/*` 缓存代理，Redis 缓存）
- `3002`：git（`raw.githubusercontent.com` 代理，支持私有仓库 Token/CORS/替换规则）

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
| ALLOWED_GH_USERS | 允许代理的 GitHub 用户（逗号分隔） |
| DEFAULT_GH_USER | 默认用户（简短路径使用） |

访问方式：
- `/gh/用户名/文件路径` - 指定用户
- `/文件路径` - 使用默认用户

### git - GitHub Raw 代理

代理 `raw.githubusercontent.com`，支持 Token 认证访问私有仓库。

| 配置项 | 说明 |
|--------|------|
| 端口 | 3002 |
| GITHUB_TOKEN | GitHub Personal Access Token |
| UPSTREAM_PATH | 默认仓库路径（如 `/用户名/仓库/分支`） |

访问方式：
- `/文件路径` - 自动拼接 UPSTREAM_PATH

### torcherino - 通用反向代理

通用反代服务，可代理 Cloudflare Pages、Hugging Face Space 等。

| 配置项 | 说明 |
|--------|------|
| 端口 | 3000 |
| DEFAULT_TARGET | 默认后端域名 |
| HOST_MAPPING | 多域名映射（JSON 格式） |
| WORKER_SECRET_KEY | 验证密钥 |

## 独立启动某个服务（可选）

如果只需要单一服务，可进入子目录使用其独立 docker-compose：

```bash
cd cdnjs && docker compose up -d     # jsDelivr 缓存
cd git && docker compose up -d       # GitHub 代理
cd torcherino && docker compose up -d # 通用反代
```

## 配置与备份

- 配置存储：SQLite（默认路径 `/data/hazuki.db`，compose 已挂载卷）
- Web 面板支持：编辑三模块配置、配置版本回滚、导入/导出备份
- 首次启动会用 `.env` 里的变量（如 `GITHUB_TOKEN`、`DEFAULT_TARGET` 等）做一次 seed；之后以 SQLite 为准
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
