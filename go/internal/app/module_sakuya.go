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
	var oplistRuntime atomic.Value
	oplistRuntime.Store(sakuyaproxy.RuntimeConfig{Host: "0.0.0.0", Port: env.initialCfg.Ports.Sakuya})

	buildOplistRuntime := func(cfg model.AppConfig, fallbackPort int) (sakuyaproxy.RuntimeConfig, error) {
		tmp := cfg
		tmp.Ports.Sakuya = fallbackPort
		return sakuyaproxy.BuildRuntimeConfig(tmp)
	}

	isOplistEnabled := func(cfg model.AppConfig) bool {
		if cfg.Sakuya.Disabled || cfg.Sakuya.Oplist.Disabled {
			return false
		}
		// Only enable when configured, to avoid breaking older configs that don't have Sakuya yet.
		if cfg.Sakuya.Oplist.Address == "" || cfg.Sakuya.Oplist.Token == "" {
			return false
		}
		return true
	}

	stateMu := &sync.Mutex{}
	var oplistServer *http.Server
	oplistPort := 0

	stopOplistServerLocked := func(shutdownCtx context.Context) {
		if oplistServer == nil {
			return
		}
		_ = oplistServer.Shutdown(shutdownCtx)
		oplistServer = nil
		oplistPort = 0
	}

	startOplistServerLocked := func(port int) {
		if port < 1 || port > 65535 {
			return
		}
		if oplistServer != nil {
			return
		}

		var h http.Handler = sakuyaproxy.NewHandler(sakuyaproxy.HandlerOptions{
			GetRuntime: func() sakuyaproxy.RuntimeConfig {
				return oplistRuntime.Load().(sakuyaproxy.RuntimeConfig)
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
		oplistServer = srv
		oplistPort = port
	}

	applyCfgLocked := func(cfg model.AppConfig) {
		if !isOplistEnabled(cfg) {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			stopOplistServerLocked(shutdownCtx)
			cancel()
		} else {
			port := cfg.Ports.Sakuya
			if oplistPort != 0 {
				port = oplistPort
			}

			next, err := buildOplistRuntime(cfg, port)
			if err != nil {
				log.Printf("sakuya: config update ignored: %v", err)
			} else {
				if oplistPort != 0 && next.Port != oplistPort {
					log.Printf("sakuya: port change requires restart (%d -> %d)", oplistPort, next.Port)
					next.Port = oplistPort
				}

				oplistRuntime.Store(next)
				if oplistServer == nil {
					startOplistServerLocked(next.Port)
				}
			}
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
			stopOplistServerLocked(shutdownCtx)
			return nil
		},
	}, nil
}
