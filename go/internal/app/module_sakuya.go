package app

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"hazuki-go/internal/metrics"
	"hazuki-go/internal/model"
	"hazuki-go/internal/proxy/sakuyaproxy"
)

type sakuyaModule struct{}

func (sakuyaModule) Name() string { return "sakuya" }

func (sakuyaModule) Start(ctx context.Context, env *runtimeEnv, _ chan<- error) (*runningModule, error) {
	var runtime atomic.Value
	runtime.Store(sakuyaproxy.RuntimeConfig{Host: "0.0.0.0", Port: env.initialCfg.Ports.Sakuya})

	buildRuntime := func(cfg model.AppConfig, fallbackPort int) (sakuyaproxy.RuntimeConfig, error) {
		tmp := cfg
		tmp.Ports.Sakuya = fallbackPort
		return sakuyaproxy.BuildRuntimeConfig(tmp)
	}

	isEnabled := func(cfg model.AppConfig) bool {
		if cfg.Sakuya.Disabled {
			return false
		}
		// Only enable when configured, to avoid breaking older configs that don't have Sakuya yet.
		if cfg.Sakuya.Oplist.Address == "" || cfg.Sakuya.Oplist.Token == "" {
			return false
		}
		return true
	}

	stateMu := &sync.Mutex{}
	var server *http.Server
	currentPort := 0

	stopServerLocked := func(shutdownCtx context.Context) {
		if server == nil {
			return
		}
		_ = server.Shutdown(shutdownCtx)
		server = nil
		currentPort = 0
	}

	startServerLocked := func(port int) {
		if port < 1 || port > 65535 {
			return
		}
		if server != nil {
			return
		}

		var h http.Handler = sakuyaproxy.NewHandler(sakuyaproxy.HandlerOptions{
			GetRuntime: func() sakuyaproxy.RuntimeConfig {
				return runtime.Load().(sakuyaproxy.RuntimeConfig)
			},
		})
		h = metrics.Wrap(env.metrics.Service("sakuya"), h)

		srv := &http.Server{
			Addr:              fmt.Sprintf("0.0.0.0:%d", port),
			Handler:           h,
			ReadHeaderTimeout: 10 * time.Second,
		}
		started, err := listenAndServe("sakuya", srv, false, nil)
		if err != nil {
			log.Printf("sakuya: start failed: %v", err)
			return
		}
		if !started {
			return
		}
		server = srv
		currentPort = port
	}

	applyCfgLocked := func(cfg model.AppConfig) {
		if !isEnabled(cfg) {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			stopServerLocked(shutdownCtx)
			cancel()
			return
		}

		port := cfg.Ports.Sakuya
		if currentPort != 0 {
			port = currentPort
		}

		next, err := buildRuntime(cfg, port)
		if err != nil {
			log.Printf("sakuya: config update ignored: %v", err)
			return
		}

		if currentPort != 0 && next.Port != currentPort {
			log.Printf("sakuya: port change requires restart (%d -> %d)", currentPort, next.Port)
			next.Port = currentPort
		}

		runtime.Store(next)
		if server == nil {
			startServerLocked(next.Port)
		}
	}

	apply := func(cfg model.AppConfig) {
		stateMu.Lock()
		defer stateMu.Unlock()
		applyCfgLocked(cfg)
	}

	apply(env.initialCfg)

	env.config.OnChanged(func(cfg model.AppConfig) {
		if ctx.Err() != nil {
			return
		}
		apply(cfg)
	})

	return &runningModule{
		name: "sakuya",
		shutdown: func(shutdownCtx context.Context) error {
			stateMu.Lock()
			defer stateMu.Unlock()
			stopServerLocked(shutdownCtx)
			return nil
		},
	}, nil
}
