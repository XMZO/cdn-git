# CDN Proxy Services

自托管的 CDN 代理服务集合，可在 VPS 上部署。

## 项目结构

```
├── cdnjs/        # jsDelivr CDN 缓存代理 (Redis)
├── git/          # GitHub raw 文件代理
└── torcherino/   # 通用反向代理 (支持 Pages/HF Space 等)
```

## 快速部署

每个服务独立部署：

```bash
# 部署 jsDelivr CDN 缓存
cd cdnjs && docker compose up -d

# 部署 GitHub raw 代理
cd git && docker compose up -d

# 部署通用反代
cd torcherino && docker compose up -d
```

## 服务说明

### cdnjs - jsDelivr CDN 缓存

代理 jsDelivr CDN，使用 Redis 缓存静态资源。

- **端口**: 3001
- **特性**: Redis 缓存、白名单用户、自动缓存 TTL

### git - GitHub Raw 代理

代理 `raw.githubusercontent.com`，支持 GitHub Token 认证。

- **端口**: 3002
- **特性**: Token 认证、私有仓库访问、域名重写

### torcherino - 通用反向代理

通用反向代理服务，可代理 Cloudflare Pages、Hugging Face Space 等任意后端。

- **端口**: 3000
- **特性**: 多域名映射、域名重写、JSON 响应处理、验证头

## License

MIT
