package app

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"

	"hazuki-go/internal/model"
	"hazuki-go/internal/proxy/cdnjsproxy"
)

type cdnjsRuntimeConfig = cdnjsproxy.RuntimeConfig

type cdnjsModule struct{}

func (cdnjsModule) Name() string { return "cdnjs" }

func (cdnjsModule) Start(_ context.Context, env *runtimeEnv, _ chan<- error) (*runningModule, error) {
	initialRuntime, err := cdnjsproxy.BuildRuntimeConfig(env.initialCfg)
	if err != nil {
		return nil, err
	}

	var runtime atomic.Value
	runtime.Store(initialRuntime)

	newRedisClient := func(runtime cdnjsproxy.RuntimeConfig) *redis.Client {
		return redis.NewClient(&redis.Options{
			Addr:         fmt.Sprintf("%s:%d", runtime.RedisHost, runtime.RedisPort),
			MaxRetries:   3,
			DialTimeout:  2 * time.Second,
			ReadTimeout:  2 * time.Second,
			WriteTimeout: 2 * time.Second,
		})
	}

	var redisClient atomic.Value
	redisClient.Store(newRedisClient(initialRuntime))

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		rc := redisClient.Load().(*redis.Client)
		if err := rc.Ping(ctx).Err(); err != nil {
			log.Printf("cdnjs redis connect failed: %v", err)
			return
		}
		log.Printf("cdnjs redis: connected to %s:%d", initialRuntime.RedisHost, initialRuntime.RedisPort)
	}()

	env.config.OnChanged(func(cfg model.AppConfig) {
		next, err := cdnjsproxy.BuildRuntimeConfig(cfg)
		if err != nil {
			log.Printf("cdnjs: config update ignored: %v", err)
			return
		}
		cur := runtime.Load().(cdnjsRuntimeConfig)
		if next.Port != cur.Port {
			log.Printf("cdnjs: port change requires restart (%d -> %d)", cur.Port, next.Port)
			next.Port = cur.Port
		}
		runtime.Store(next)

		if next.RedisHost != cur.RedisHost || next.RedisPort != cur.RedisPort {
			old := redisClient.Load().(*redis.Client)
			redisClient.Store(newRedisClient(next))
			go func() { _ = old.Close() }()

			go func(host string, port int) {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				rc := redisClient.Load().(*redis.Client)
				if err := rc.Ping(ctx).Err(); err != nil {
					log.Printf("cdnjs redis connect failed: %v", err)
					return
				}
				log.Printf("cdnjs redis: connected to %s:%d", host, port)
			}(next.RedisHost, next.RedisPort)
		}
	})

	server := &http.Server{
		Addr: fmt.Sprintf("0.0.0.0:%d", initialRuntime.Port),
		Handler: cdnjsproxy.NewDynamicHandler(
			func() cdnjsproxy.RuntimeConfig { return runtime.Load().(cdnjsRuntimeConfig) },
			func() *redis.Client { return redisClient.Load().(*redis.Client) },
		),
		ReadHeaderTimeout: 10 * time.Second,
	}

	started, err := listenAndServe("cdnjs", server, false, nil)
	if err != nil {
		return nil, err
	}

	return &runningModule{
		name:    "cdnjs",
		started: started,
		shutdown: func(ctx context.Context) error {
			if !started {
				return nil
			}
			return server.Shutdown(ctx)
		},
		close: func() error {
			if rc, ok := redisClient.Load().(*redis.Client); ok && rc != nil {
				return rc.Close()
			}
			return nil
		},
	}, nil
}
