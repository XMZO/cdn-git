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

	"github.com/redis/go-redis/v9"

	"hazuki-go/internal/model"
	"hazuki-go/internal/proxy/cdnjsproxy"
)

type cdnjsModule struct{}

func (m cdnjsModule) Name() string { return "cdnjs" }

func (m cdnjsModule) Start(ctx context.Context, env *runtimeEnv, _ chan<- error) (*runningModule, error) {
	var runtime atomic.Value
	runtime.Store(cdnjsproxy.RuntimeConfig{Host: "0.0.0.0", Port: env.initialCfg.Ports.Cdnjs})

	var redisClient atomic.Value
	redisClient.Store((*redis.Client)(nil))

	newRedisClient := func(rc cdnjsproxy.RuntimeConfig) *redis.Client {
		return redis.NewClient(&redis.Options{
			Addr:         fmt.Sprintf("%s:%d", rc.RedisHost, rc.RedisPort),
			MaxRetries:   3,
			DialTimeout:  2 * time.Second,
			ReadTimeout:  2 * time.Second,
			WriteTimeout: 2 * time.Second,
		})
	}

	stateMu := &sync.Mutex{}
	var server *http.Server
	currentPort := 0
	currentRedisAddr := ""

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

		srv := &http.Server{
			Addr: fmt.Sprintf("0.0.0.0:%d", port),
			Handler: cdnjsproxy.NewDynamicHandler(
				func() cdnjsproxy.RuntimeConfig {
					return runtime.Load().(cdnjsproxy.RuntimeConfig)
				},
				func() *redis.Client {
					rc, _ := redisClient.Load().(*redis.Client)
					return rc
				},
			),
			ReadHeaderTimeout: 10 * time.Second,
		}

		started, err := listenAndServe("cdnjs", srv, false, nil)
		if err != nil {
			log.Printf("cdnjs: start failed: %v", err)
			return
		}
		if !started {
			return
		}
		server = srv
		currentPort = port
	}

	closeRedisLocked := func() {
		old, _ := redisClient.Load().(*redis.Client)
		redisClient.Store((*redis.Client)(nil))
		currentRedisAddr = ""
		if old != nil {
			_ = old.Close()
		}
	}

	apply := func(cfg model.AppConfig) {
		stateMu.Lock()
		defer stateMu.Unlock()

		if cfg.Cdnjs.Disabled {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			stopServerLocked(shutdownCtx)
			closeRedisLocked()
			return
		}

		port := cfg.Ports.Cdnjs
		if currentPort != 0 {
			port = currentPort
		}

		tmp := cfg
		tmp.Ports.Cdnjs = port
		next, err := cdnjsproxy.BuildRuntimeConfig(tmp)
		if err != nil {
			log.Printf("cdnjs: config update ignored: %v", err)
			return
		}
		if currentPort != 0 && next.Port != currentPort {
			log.Printf("cdnjs: port change requires restart (%d -> %d)", currentPort, next.Port)
			next.Port = currentPort
		}

		runtime.Store(next)

		desiredAddr := fmt.Sprintf("%s:%d", next.RedisHost, next.RedisPort)
		if strings.TrimSpace(desiredAddr) != "" && desiredAddr != currentRedisAddr {
			old, _ := redisClient.Load().(*redis.Client)
			newClient := newRedisClient(next)
			redisClient.Store(newClient)
			currentRedisAddr = desiredAddr
			if old != nil {
				_ = old.Close()
			}

			go func(addr string, rc *redis.Client) {
				cctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				if err := rc.Ping(cctx).Err(); err != nil {
					log.Printf("cdnjs redis connect failed: %v", err)
					return
				}
				log.Printf("cdnjs redis: connected to %s", addr)
			}(desiredAddr, newClient)
		}

		if server == nil {
			startServerLocked(next.Port)
		}
	}

	apply(env.initialCfg)

	env.config.OnChanged(func(cfg model.AppConfig) {
		if ctx.Err() != nil {
			return
		}
		apply(cfg)
	})

	return &runningModule{
		name: "cdnjs",
		shutdown: func(shutdownCtx context.Context) error {
			stateMu.Lock()
			defer stateMu.Unlock()

			stopServerLocked(shutdownCtx)

			old, _ := redisClient.Load().(*redis.Client)
			redisClient.Store((*redis.Client)(nil))
			currentRedisAddr = ""
			if old != nil {
				return old.Close()
			}
			return nil
		},
	}, nil
}
