# Hazuki (Go rewrite)

This folder contains the Go rewrite of Hazuki.

## Requirements

- Go 1.24+

## Run (dev)

```bash
cd go
cp .env.example .env
go run ./cmd/hazuki
```

## Run (Docker Compose)

```bash
cd go
cp .env.example .env
docker compose up -d --build
```

Then open:

- Admin panel: `http://127.0.0.1:3100`
- Wizard: `http://127.0.0.1:3100/wizard`
- System: `http://127.0.0.1:3100/system`
- Cdnjs proxy: `http://127.0.0.1:3001`
- Git proxy: `http://127.0.0.1:3002`
- Torcherino proxy: `http://127.0.0.1:3000`

## Admin username/password

- First run: go to `/setup` to create an admin user
- Or set env vars before first start: `HAZUKI_ADMIN_USERNAME` / `HAZUKI_ADMIN_PASSWORD`

## Notes

- Config is stored in SQLite (`HAZUKI_DB_PATH`, default: `data/hazuki.db` relative to your working dir). With Docker Compose, the DB file is `./data/hazuki.db` on the host (bind mounted to `/data`).
- Config changes apply immediately (hot reload). Port changes require a process restart.
- `HAZUKI_MASTER_KEY` enables at-rest encryption for secrets stored as `enc:v1:...`. If you need to change it, rotate it in the web panel (`/system`) so existing data gets re-encrypted. Hazuki will try to update `.env` automatically (Docker Compose mounts it by default), but still verify your startup env is in sync for the next restart.
- `cdnjs` cache TTL is suffix-based (compatible with the Node defaults) and can be overridden in the admin panel (`Default TTL` + `TTL Overrides`).
- Admin panel features: `wizard`, `system` status (services + Redis), `torcherino/cdnjs/git` configs, `versions` rollback, `export/import` backup, `account` password change.
- Redis is optional but recommended for `cdnjs` caching. If you run without Docker, set `REDIS_HOST=127.0.0.1` (or change it in the web panel) and make sure Redis is running.
