package app

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"hazuki-go/internal/metrics"
	"hazuki-go/internal/model"
	"hazuki-go/internal/proxy/patchouliproxy"
)

type patchouliModule struct{}

func (patchouliModule) Name() string { return "patchouli" }

func (patchouliModule) Start(ctx context.Context, env *runtimeEnv, _ chan<- error) (*runningModule, error) {
	var runtime atomic.Value
	runtime.Store(patchouliproxy.RuntimeConfig{Host: "0.0.0.0", Port: env.initialCfg.Ports.Patchouli, Disabled: true})

	buildRuntime := func(cfg model.AppConfig, fallbackPort int) (patchouliproxy.RuntimeConfig, error) {
		tmp := cfg
		tmp.Ports.Patchouli = fallbackPort
		return patchouliproxy.BuildRuntimeConfig(tmp)
	}

	isEnabled := func(cfg model.AppConfig) bool {
		if cfg.Patchouli.Disabled {
			return false
		}
		return strings.TrimSpace(cfg.Patchouli.Repo) != ""
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

		h := patchouliproxy.NewDynamicHandler(func() patchouliproxy.RuntimeConfig {
			return runtime.Load().(patchouliproxy.RuntimeConfig)
		})
		h = metrics.Wrap(env.metrics.Service("patchouli"), h)

		srv := &http.Server{
			Addr:              fmt.Sprintf("0.0.0.0:%d", port),
			Handler:           h,
			ReadHeaderTimeout: 10 * time.Second,
		}

		started, err := listenAndServe("patchouli", srv, false, nil)
		if err != nil {
			log.Printf("patchouli: start failed: %v", err)
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

		port := cfg.Ports.Patchouli
		if port == 0 {
			port = 3201
		}
		if currentPort != 0 {
			port = currentPort
		}

		next, err := buildRuntime(cfg, port)
		if err != nil {
			log.Printf("patchouli: config update ignored: %v", err)
			return
		}
		if currentPort != 0 && next.Port != currentPort {
			log.Printf("patchouli: port change requires restart (%d -> %d)", currentPort, next.Port)
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
		name: "patchouli",
		shutdown: func(shutdownCtx context.Context) error {
			stateMu.Lock()
			defer stateMu.Unlock()
			stopServerLocked(shutdownCtx)
			return nil
		},
	}, nil
}
