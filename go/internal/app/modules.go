package app

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
)

type module interface {
	Name() string
	Start(ctx context.Context, env *runtimeEnv, fatalErrCh chan<- error) (*runningModule, error)
}

type runningModule struct {
	name     string
	started  bool
	shutdown func(context.Context) error
	close    func() error
}

func (m *runningModule) Stop(ctx context.Context) {
	if m == nil {
		return
	}
	if m.shutdown != nil {
		_ = m.shutdown(ctx)
	}
	if m.close != nil {
		_ = m.close()
	}
}

func listenAndServe(name string, server *http.Server, required bool, fatalErrCh chan<- error) (started bool, err error) {
	ln, err := net.Listen("tcp", server.Addr)
	if err != nil {
		if required {
			return false, fmt.Errorf("%s listen %s: %w", name, server.Addr, err)
		}
		log.Printf("%s: listen failed on %s: %v (service disabled; change port and restart)", name, server.Addr, err)
		return false, nil
	}

	go func() {
		log.Printf("%s: listening on http://%s", name, server.Addr)
		if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
			if required && fatalErrCh != nil {
				fatalErrCh <- err
				return
			}
			log.Printf("%s: server stopped: %v", name, err)
		}
	}()

	return true, nil
}
