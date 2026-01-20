package app

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"hazuki-go/internal/admin"
)

type adminModule struct{}

func (adminModule) Name() string { return "admin" }

func (adminModule) Start(_ context.Context, env *runtimeEnv, fatalErrCh chan<- error) (*runningModule, error) {
	handler, err := admin.NewHandler(admin.Options{
		DB:         env.db,
		Config:     env.config,
		Port:       env.initialCfg.Ports.Admin,
		SessionTTL: env.sessionTTL,
	})
	if err != nil {
		return nil, err
	}

	server := &http.Server{
		Addr:              fmt.Sprintf("0.0.0.0:%d", env.initialCfg.Ports.Admin),
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	started, err := listenAndServe("admin", server, true, fatalErrCh)
	if err != nil {
		return nil, err
	}
	if !started {
		return nil, fmt.Errorf("admin: failed to start")
	}

	return &runningModule{
		name:    "admin",
		started: true,
		shutdown: func(ctx context.Context) error {
			return server.Shutdown(ctx)
		},
	}, nil
}

