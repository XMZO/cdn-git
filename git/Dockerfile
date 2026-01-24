# NOTE: 这是旧的独立实现（维护模式）。当前部署请使用仓库根目录 README 指引（`go/` 目录的部署文件）。
FROM node:20-alpine

WORKDIR /app

# 复制依赖文件
COPY package*.json ./

# 安装依赖
RUN npm ci --omit=dev

# 复制源码
COPY server.js ./

ENV PORT=3000
ENV HOST=0.0.0.0
ENV UPSTREAM=raw.githubusercontent.com
ENV UPSTREAM_MOBILE=raw.githubusercontent.com

EXPOSE 3000
CMD ["node", "server.js"]
