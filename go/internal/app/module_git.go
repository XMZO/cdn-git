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

	"hazuki-go/internal/model"
	"hazuki-go/internal/proxy/gitproxy"
)

type gitModule struct{}

func (gitModule) Name() string { return "git" }

type gitInstanceRuntime struct {
	key         string // "default" or instance id
	displayName string // for logs
	runtime     atomic.Value
	server      *http.Server
	currentPort int
}

func (gitModule) Start(ctx context.Context, env *runtimeEnv, _ chan<- error) (*runningModule, error) {
	stateMu := &sync.Mutex{}
	instances := map[string]*gitInstanceRuntime{}

	stopInstanceLocked := func(inst *gitInstanceRuntime, shutdownCtx context.Context) {
		if inst == nil {
			return
		}
		if inst.server != nil {
			_ = inst.server.Shutdown(shutdownCtx)
			inst.server = nil
		}
		inst.currentPort = 0
	}

	buildRuntime := func(cfg model.AppConfig, port int, gitCfg model.GitConfig) (gitproxy.RuntimeConfig, error) {
		tmp := cfg
		tmp.Ports.Git = port
		tmp.Git = gitCfg
		return gitproxy.BuildRuntimeConfig(tmp)
	}

	ensureInstanceLocked := func(key, displayName string, port int) *gitInstanceRuntime {
		inst := instances[key]
		if inst != nil {
			return inst
		}
		inst = &gitInstanceRuntime{key: key, displayName: displayName}
		inst.runtime.Store(gitproxy.RuntimeConfig{Host: "0.0.0.0", Port: port})
		instances[key] = inst
		return inst
	}

	startServerLocked := func(inst *gitInstanceRuntime, port int) {
		if inst == nil || port < 1 || port > 65535 {
			return
		}
		if inst.server != nil {
			return
		}

		server := &http.Server{
			Addr: fmt.Sprintf("0.0.0.0:%d", port),
			Handler: gitproxy.NewDynamicHandler(func() gitproxy.RuntimeConfig {
				return inst.runtime.Load().(gitproxy.RuntimeConfig)
			}),
			ReadHeaderTimeout: 10 * time.Second,
		}

		started, err := listenAndServe(inst.displayName, server, false, nil)
		if err != nil {
			log.Printf("%s: start failed: %v", inst.displayName, err)
			return
		}
		if !started {
			return
		}
		inst.server = server
		inst.currentPort = port
	}

	applyCfgLocked := func(cfg model.AppConfig) {
		desired := map[string]struct{}{}

		// default instance
		if !cfg.Git.Disabled {
			key := "default"
			desired[key] = struct{}{}

			port := cfg.Ports.Git
			inst := ensureInstanceLocked(key, "git", port)
			if inst.currentPort != 0 {
				port = inst.currentPort
			}

			next, err := buildRuntime(cfg, port, cfg.Git)
			if err != nil {
				log.Printf("git: config update ignored: %v", err)
			} else {
				if inst.currentPort != 0 && next.Port != inst.currentPort {
					log.Printf("git: port change requires restart (%d -> %d)", inst.currentPort, next.Port)
					next.Port = inst.currentPort
				}
				inst.runtime.Store(next)
				if inst.server == nil {
					startServerLocked(inst, next.Port)
				}
			}
		} else {
			if inst, ok := instances["default"]; ok {
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				stopInstanceLocked(inst, shutdownCtx)
				delete(instances, "default")
			}
		}

		// extra instances
		for _, raw := range cfg.GitInstances {
			id := strings.TrimSpace(raw.ID)
			if id == "" {
				continue
			}
			key := "inst:" + strings.ToLower(id)
			if raw.Git.Disabled {
				if inst, ok := instances[key]; ok {
					shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					stopInstanceLocked(inst, shutdownCtx)
					delete(instances, key)
				}
				continue
			}

			desired[key] = struct{}{}

			display := "git[" + id + "]"
			port := raw.Port
			inst := ensureInstanceLocked(key, display, port)
			if inst.currentPort != 0 {
				port = inst.currentPort
			}

			next, err := buildRuntime(cfg, port, raw.Git)
			if err != nil {
				log.Printf("%s: config update ignored: %v", display, err)
				continue
			}
			if inst.currentPort != 0 && next.Port != inst.currentPort {
				log.Printf("%s: port change requires restart (%d -> %d)", display, inst.currentPort, next.Port)
				next.Port = inst.currentPort
			}

			inst.runtime.Store(next)
			if inst.server == nil {
				startServerLocked(inst, next.Port)
			}
		}

		// stop removed instances
		for key, inst := range instances {
			if _, ok := desired[key]; ok {
				continue
			}
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			stopInstanceLocked(inst, shutdownCtx)
			cancel()
			delete(instances, key)
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
		name: "git",
		shutdown: func(shutdownCtx context.Context) error {
			stateMu.Lock()
			defer stateMu.Unlock()
			for _, inst := range instances {
				stopInstanceLocked(inst, shutdownCtx)
			}
			clear(instances)
			return nil
		},
	}, nil
}
