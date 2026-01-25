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

	"hazuki-go/internal/metrics"
	"hazuki-go/internal/model"
	"hazuki-go/internal/proxy/torcherinoproxy"
)

type torcherinoModule struct{}

func (torcherinoModule) Name() string { return "torcherino" }

func (torcherinoModule) Start(_ context.Context, env *runtimeEnv, _ chan<- error) (*runningModule, error) {
	var runtime atomic.Value
	runtime.Store(torcherinoproxy.RuntimeConfig{Host: "0.0.0.0", Port: env.initialCfg.Ports.Torcherino})

	var redisClient atomic.Value
	redisClient.Store((*redis.Client)(nil))

	buildRuntime := func(cfg model.AppConfig, fallbackPort int) (torcherinoproxy.RuntimeConfig, error) {
		tmp := cfg
		tmp.Ports.Torcherino = fallbackPort
		return torcherinoproxy.BuildRuntimeConfig(tmp)
	}

	stateMu := &sync.Mutex{}
	var server *http.Server
	currentPort := 0
	currentRedisAddr := ""

	newRedisClient := func(rc torcherinoproxy.RuntimeConfig) *redis.Client {
		return redis.NewClient(&redis.Options{
			Addr:         fmt.Sprintf("%s:%d", rc.RedisCache.Host, rc.RedisCache.Port),
			MaxRetries:   3,
			DialTimeout:  2 * time.Second,
			ReadTimeout:  2 * time.Second,
			WriteTimeout: 2 * time.Second,
		})
	}

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

	closeRedis := func() {
		old, _ := redisClient.Load().(*redis.Client)
		redisClient.Store((*redis.Client)(nil))
		currentRedisAddr = ""
		if old != nil {
			_ = old.Close()
		}
	}

	startServer := func(port int) {
		if port < 1 || port > 65535 {
			return
		}
		h := torcherinoproxy.NewDynamicHandler(
			func() torcherinoproxy.RuntimeConfig {
				return runtime.Load().(torcherinoproxy.RuntimeConfig)
			},
			func() *redis.Client {
				rc, _ := redisClient.Load().(*redis.Client)
				return rc
			},
		)
		h = metrics.Wrap(env.metrics.Service("torcherino"), h)
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
			closeRedis()
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

		if next.RedisCache.Enabled {
			desiredAddr := fmt.Sprintf("%s:%d", next.RedisCache.Host, next.RedisCache.Port)
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
						log.Printf("torcherino redis connect failed: %v", err)
						return
					}
					log.Printf("torcherino redis: connected to %s", addr)
				}(desiredAddr, newClient)
			}
		} else {
			closeRedis()
		}

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
				closeRedis()
				return nil
			}
			err := server.Shutdown(ctx)
			server = nil
			currentPort = 0
			closeRedis()
			return err
		},
	}, nil
}
