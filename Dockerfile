FROM node:20-bookworm-slim

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY src ./src

ENV NODE_ENV=production
ENV AKARI_DB_PATH=/data/akari.db

EXPOSE 3100 3000 3001 3002

CMD ["node", "src/index.js"]

