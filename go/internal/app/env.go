package app

import (
	"database/sql"

	"hazuki-go/internal/metrics"
	"hazuki-go/internal/model"
	"hazuki-go/internal/storage"
	"hazuki-go/internal/traffic"
)

type runtimeEnv struct {
	db         *sql.DB
	config     *storage.ConfigStore
	initialCfg model.AppConfig
	sessionTTL int
	metrics    *metrics.Registry
	traffic    *traffic.Persister
}
