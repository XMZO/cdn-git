# Hazuki Proxy Suite

<p align="center">
  <a href="https://github.com/XMZO/Hazuki">
    <img src="./avatar.png" alt="Hazuki" width="160" />
  </a>
</p>

Hazuki 是一个 **单进程多端口** 的代理套件：内置 SQLite 配置中心 + Web 面板（热更新/版本回滚/导入导出/状态检测），把常用的几个代理能力做成可配置模块。

## 快速部署（Docker Compose）

```bash
cd go
cp .env.example .env
docker compose up -d --build
```

启动后打开：

- 面板：`http://你的服务器:3100`
- 快速向导：`http://你的服务器:3100/wizard`
- 系统状态：`http://你的服务器:3100/system`

> 配置除端口外会热更新立即生效；端口修改需要重启进程/容器。

## 默认端口

- `3100`：Admin 面板
- `3000`：Torcherino（通用反代）
- `3001`：Cdnjs（jsDelivr 缓存代理，Redis 缓存）
- `3002`：Git（GitHub Raw 代理，支持 Token/CORS/替换规则）
- `3200`：Sakuya · Oplist（OpenList 直链加速）

## 健康检查

- admin：`http://HOST:3100/_hazuki/health`
- torcherino：`http://HOST:3000/_hazuki/health`
- cdnjs：`http://HOST:3001/_hazuki/health`
- git：`http://HOST:3002/_hazuki/health`
- sakuya (oplist)：`http://HOST:3200/_hazuki/health`

## 配置与账号

- 首次启动会用 `go/.env` 做一次 seed；之后以 SQLite 为准（DB 默认 `go/data/hazuki.db`；Docker Compose 会 bind mount 到 `go/data/`）。
- 第一次访问会引导到 `http://你的服务器:3100/setup` 创建管理员；也可在 `go/.env` 里提前设置 `HAZUKI_ADMIN_USERNAME` / `HAZUKI_ADMIN_PASSWORD`（仅第一次生效）。
- 如需敏感配置落盘加密：设置 `HAZUKI_MASTER_KEY`（面板 `/system` 支持轮换）。

更详细的模块说明与配置项：见 `go/README.md`。

## Nginx 反代示例（以 cdnjs 为例）

```nginx
location / {
    proxy_pass http://127.0.0.1:3001;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

## 仓库结构

```
├── go/            # Hazuki 主程序（推荐）
├── src/           # 旧实现（维护模式，仅保留兼容）
├── cdnjs/         # 旧：独立版本（参考）
├── git/           # 旧：独立版本（参考）
└── torcherino/    # 旧：独立版本（参考）
```

> 根目录的 `Dockerfile` / `docker-compose.yml` 对应旧实现；推荐使用 `go/` 目录下的部署文件。

## License

MIT
