FROM node:20-alpine

WORKDIR /app

# 安装 pnpm
RUN corepack enable && corepack prepare pnpm@latest --activate

# 复制依赖文件
COPY package.json pnpm-lock.yaml ./

# 安装依赖
RUN pnpm install --frozen-lockfile --prod

# 复制源码
COPY server.js ./

ENV PORT=3000
ENV REDIS_HOST=127.0.0.1
ENV REDIS_PORT=6379

EXPOSE 3000
CMD ["node", "server.js"]
