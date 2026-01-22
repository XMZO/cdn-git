package app

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"hazuki-go/internal/admin"
	"hazuki-go/internal/metrics"
)

type adminModule struct{}

func (adminModule) Name() string { return "admin" }

func (adminModule) Start(_ context.Context, env *runtimeEnv, fatalErrCh chan<- error) (*runningModule, error) {
	handler, err := admin.NewHandler(admin.Options{
		DB:         env.db,
		Config:     env.config,
		Port:       env.initialCfg.Ports.Admin,
		SessionTTL: env.sessionTTL,
		Metrics:    env.metrics,
	})
	if err != nil {
		return nil, err
	}

	handler = metrics.Wrap(env.metrics.Service("admin"), handler)

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
