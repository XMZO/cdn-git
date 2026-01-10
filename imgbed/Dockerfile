FROM node:20-alpine

WORKDIR /app
COPY package.json server.js ./

ENV PORT=3000
ENV DEFAULT_TARGET=xxxxxxxxxxxxxxxxx.hf.space

EXPOSE 3000
CMD ["node", "server.js"]
