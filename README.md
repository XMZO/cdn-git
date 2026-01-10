# CDN Proxy Services

自托管的 CDN 代理服务集合，可在 VPS 上通过 Docker 部署。

## 项目结构

```
├── cdnjs/        # jsDelivr CDN 缓存代理 (Redis)
├── git/          # GitHub raw 文件代理（支持私有仓库）
└── torcherino/   # 通用反向代理 (Pages/HF Space 等)
```

## 快速部署

### 一键启动所有服务

```bash
# 1. 克隆项目
git clone https://github.com/你的用户名/cdn-git.git
cd cdn-git

# 2. 为每个项目创建配置
cp cdnjs/.env.example cdnjs/.env
cp git/.env.example git/.env
cp torcherino/.env.example torcherino/.env

# 3. 编辑配置文件
nano cdnjs/.env
nano git/.env
nano torcherino/.env

# 4. 一键启动所有服务
docker compose up -d
```

### 单独启动某个服务

```bash
cd cdnjs && docker compose up -d     # jsDelivr 缓存
cd git && docker compose up -d       # GitHub 代理
cd torcherino && docker compose up -d # 通用反代
```

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
