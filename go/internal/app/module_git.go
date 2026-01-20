package app

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync/atomic"
	"time"

	"hazuki-go/internal/model"
	"hazuki-go/internal/proxy/gitproxy"
)

type gitModule struct{}

func (gitModule) Name() string { return "git" }

func (gitModule) Start(_ context.Context, env *runtimeEnv, _ chan<- error) (*runningModule, error) {
	initialRuntime, err := gitproxy.BuildRuntimeConfig(env.initialCfg)
	if err != nil {
		return nil, err
	}

	var runtime atomic.Value
	runtime.Store(initialRuntime)

	env.config.OnChanged(func(cfg model.AppConfig) {
		next, err := gitproxy.BuildRuntimeConfig(cfg)
		if err != nil {
			log.Printf("git: config update ignored: %v", err)
			return
		}
		cur := runtime.Load().(gitproxy.RuntimeConfig)
		if next.Port != cur.Port {
			log.Printf("git: port change requires restart (%d -> %d)", cur.Port, next.Port)
			next.Port = cur.Port
		}
		runtime.Store(next)
	})

	server := &http.Server{
		Addr:              fmt.Sprintf("0.0.0.0:%d", initialRuntime.Port),
		Handler:           gitproxy.NewDynamicHandler(func() gitproxy.RuntimeConfig { return runtime.Load().(gitproxy.RuntimeConfig) }),
		ReadHeaderTimeout: 10 * time.Second,
	}

	started, err := listenAndServe("git", server, false, nil)
	if err != nil {
		return nil, err
	}

	return &runningModule{
		name:    "git",
		started: started,
		shutdown: func(ctx context.Context) error {
			if !started {
				return nil
			}
			return server.Shutdown(ctx)
		},
	}, nil
}
