package app

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync/atomic"
	"time"

	"hazuki-go/internal/model"
	"hazuki-go/internal/proxy/torcherinoproxy"
)

type torcherinoModule struct{}

func (torcherinoModule) Name() string { return "torcherino" }

func (torcherinoModule) Start(_ context.Context, env *runtimeEnv, _ chan<- error) (*runningModule, error) {
	initialRuntime, err := torcherinoproxy.BuildRuntimeConfig(env.initialCfg)
	if err != nil {
		return nil, err
	}

	var runtime atomic.Value
	runtime.Store(initialRuntime)

	env.config.OnChanged(func(cfg model.AppConfig) {
		next, err := torcherinoproxy.BuildRuntimeConfig(cfg)
		if err != nil {
			log.Printf("torcherino: config update ignored: %v", err)
			return
		}
		cur := runtime.Load().(torcherinoproxy.RuntimeConfig)
		if next.Port != cur.Port {
			log.Printf("torcherino: port change requires restart (%d -> %d)", cur.Port, next.Port)
			next.Port = cur.Port
		}
		runtime.Store(next)
	})

	server := &http.Server{
		Addr:              fmt.Sprintf("0.0.0.0:%d", initialRuntime.Port),
		Handler:           torcherinoproxy.NewDynamicHandler(func() torcherinoproxy.RuntimeConfig { return runtime.Load().(torcherinoproxy.RuntimeConfig) }),
		ReadHeaderTimeout: 10 * time.Second,
	}

	started, err := listenAndServe("torcherino", server, false, nil)
	if err != nil {
		return nil, err
	}

	return &runningModule{
		name:    "torcherino",
		started: started,
		shutdown: func(ctx context.Context) error {
			if !started {
				return nil
			}
			return server.Shutdown(ctx)
		},
	}, nil
}

