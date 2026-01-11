# git (legacy) ↔ Akari 兼容启动

本目录下的 `server.js` 是旧版 `cdn-git/git` 代理服务（基于 `.env`）。

如果你已经把 Akari 合并到仓库根目录的 `akari/`，并且希望继续使用旧版 `server.js`，但配置改由 Akari 的 SQLite/Web 面板统一管理，可以使用下面的兼容入口：

## 启动方式

在仓库根目录执行（或进入 `git/` 执行也可以）：

```bash
node git/akari-compat.js
```

该脚本会：

1. 读取 `../akari/data/akari.db`（或 `AKARI_DB_PATH` 指定的路径）
2. 取出其中的 Git 配置并映射为旧版 `server.js` 所需环境变量（`UPSTREAM_PATH`、`GITHUB_TOKEN`、CORS、缓存策略等）
3. 直接 `require("./server.js")` 启动旧服务（无需改旧代码）

## 可选：直接跑 Akari 版本的 git（推荐）

如果你不需要旧版 `server.js`，希望用 Akari 的实现（支持 `/_akari/health` 与配置热更新监听），可以直接启动：

```bash
node git/akari-git.js
```

## 需要的环境变量

- `AKARI_DB_PATH`（可选）：Akari 的 SQLite 路径；不填默认 `akari/data/akari.db`
- `AKARI_MASTER_KEY`（可选但推荐）：如果你的 Akari 数据库里存了 `enc:v1:...` 的敏感字段（如 Token），必须提供同一个 `AKARI_MASTER_KEY` 才能解密
- `AKARI_COMPAT_PREFER_ENV=1`（可选）：优先使用当前进程已有环境变量（不覆盖），默认以 Akari 数据库为准覆盖

## 注意

- 旧版 `server.js` 不支持热加载：你在 Akari 面板修改 Git 配置后，需要重启该进程/容器才能生效。
- 该脚本依赖 `akari/` 的 node_modules（包含 `better-sqlite3`）。如提示缺依赖，请先在 `akari/` 下执行一次 `npm install`。
- 该脚本默认会把 `PORT` 设置为 Akari 配置里的 `ports.git`（默认 `3002`）。如果你仍在使用旧版 `git/docker-compose.yml` 的端口映射（`3002:3000`），请改映射或用 `AKARI_COMPAT_PREFER_ENV=1` 保留原来的 `PORT=3000`。
