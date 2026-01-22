package app

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"hazuki-go/internal/model"
	"hazuki-go/internal/proxy/torcherinoproxy"
)

type torcherinoModule struct{}

func (torcherinoModule) Name() string { return "torcherino" }

func (torcherinoModule) Start(_ context.Context, env *runtimeEnv, _ chan<- error) (*runningModule, error) {
	var runtime atomic.Value
	runtime.Store(torcherinoproxy.RuntimeConfig{Host: "0.0.0.0", Port: env.initialCfg.Ports.Torcherino})

	buildRuntime := func(cfg model.AppConfig, fallbackPort int) (torcherinoproxy.RuntimeConfig, error) {
		tmp := cfg
		tmp.Ports.Torcherino = fallbackPort
		return torcherinoproxy.BuildRuntimeConfig(tmp)
	}

	stateMu := &sync.Mutex{}
	var server *http.Server
	currentPort := 0

	stopServer := func() {
		if server == nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		server = nil
		currentPort = 0
	}

	startServer := func(port int) {
		if port < 1 || port > 65535 {
			return
		}
		h := torcherinoproxy.NewDynamicHandler(func() torcherinoproxy.RuntimeConfig {
			return runtime.Load().(torcherinoproxy.RuntimeConfig)
		})
		srv := &http.Server{
			Addr:              fmt.Sprintf("0.0.0.0:%d", port),
			Handler:           h,
			ReadHeaderTimeout: 10 * time.Second,
		}
		started, err := listenAndServe("torcherino", srv, false, nil)
		if err != nil {
			log.Printf("torcherino: start failed: %v", err)
			return
		}
		if !started {
			return
		}
		server = srv
		currentPort = port
	}

	apply := func(cfg model.AppConfig) {
		stateMu.Lock()
		defer stateMu.Unlock()

		if cfg.Torcherino.Disabled {
			stopServer()
			return
		}

		// Build runtime config; if invalid, ignore updates.
		port := cfg.Ports.Torcherino
		if currentPort != 0 {
			port = currentPort
		}
		next, err := buildRuntime(cfg, port)
		if err != nil {
			log.Printf("torcherino: config update ignored: %v", err)
			return
		}

		// Port changes require restart when running.
		if currentPort != 0 && next.Port != currentPort {
			log.Printf("torcherino: port change requires restart (%d -> %d)", currentPort, next.Port)
			next.Port = currentPort
		}
		runtime.Store(next)

		if server == nil {
			startServer(next.Port)
		}
	}

	apply(env.initialCfg)

	env.config.OnChanged(func(cfg model.AppConfig) {
		apply(cfg)
	})

	return &runningModule{
		name: "torcherino",
		shutdown: func(ctx context.Context) error {
			stateMu.Lock()
			defer stateMu.Unlock()
			if server == nil {
				return nil
			}
			err := server.Shutdown(ctx)
			server = nil
			currentPort = 0
			return err
		},
	}, nil
}
