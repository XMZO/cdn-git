package app

import (
	"context"
	"time"

	"hazuki-go/internal/traffic"
)

type trafficModule struct{}

func (trafficModule) Name() string { return "traffic" }

func (trafficModule) Start(ctx context.Context, env *runtimeEnv, _ chan<- error) (*runningModule, error) {
	p := traffic.NewPersister(env.db, env.metrics)
	if err := p.Init(ctx); err != nil {
		return nil, err
	}
	p.ResetBaseline()
	env.traffic = p

	stop := p.Start(ctx, traffic.Options{
		FlushInterval:   5 * time.Second,
		CleanupInterval: 1 * time.Hour,
	})

	return &runningModule{
		name:    "traffic",
		started: true,
		shutdown: func(context.Context) error {
			stop()
			return nil
		},
	}, nil
}

