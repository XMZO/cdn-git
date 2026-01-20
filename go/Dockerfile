FROM golang:1.24-bookworm AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags "-s -w" -o /out/hazuki-go ./cmd/hazuki

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /out/hazuki-go /app/hazuki-go

ENV HAZUKI_DB_PATH=/data/hazuki.db

EXPOSE 3100 3000 3001 3002

CMD ["/app/hazuki-go"]

