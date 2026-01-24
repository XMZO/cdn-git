# NOTE: 这是旧的独立实现（维护模式）。当前部署请使用仓库根目录 README 指引（`go/` 目录的部署文件）。
FROM node:20-alpine

WORKDIR /app
COPY package.json server.js ./

ENV PORT=3000
ENV DEFAULT_TARGET=xxxxxxxxxxxxxxxxx.hf.space

EXPOSE 3000
CMD ["node", "server.js"]
