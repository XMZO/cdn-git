# Akari Proxy Suite

把 `cdnjs`、`git`、`torcherino` 三个代理服务合并为一个大项目：同一进程多端口运行 + SQLite 配置中心 + Web 面板。

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
- 或者在 `.env` 里提前设置 `AKARI_ADMIN_USERNAME` / `AKARI_ADMIN_PASSWORD`，首次启动会自动创建（仅第一次）

## 配置与备份

- 配置存储：SQLite（默认路径 `/data/akari.db`，compose 已挂载卷）
- Web 面板支持：编辑三模块配置、配置版本回滚、导入/导出备份
- 首次启动会用 `.env` 里的旧变量（如 `GITHUB_TOKEN`、`DEFAULT_TARGET` 等）做一次 seed；之后以 SQLite 为准
- 若数据库里存在加密的敏感配置（形如 `enc:v1:...`），启动时必须提供同一个 `AKARI_MASTER_KEY`，否则会直接退出

## License

MIT
