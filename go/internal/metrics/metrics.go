package metrics

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
)

type Snapshot struct {
	BytesIn  int64 `json:"bytesIn"`
	BytesOut int64 `json:"bytesOut"`
	Requests int64 `json:"requests"`
}

type Service struct {
	key string

	bytesIn  atomic.Int64
	bytesOut atomic.Int64
	requests atomic.Int64
}

func (s *Service) Key() string {
	if s == nil {
		return ""
	}
	return s.key
}

func (s *Service) Snapshot() Snapshot {
	if s == nil {
		return Snapshot{}
	}
	return Snapshot{
		BytesIn:  s.bytesIn.Load(),
		BytesOut: s.bytesOut.Load(),
		Requests: s.requests.Load(),
	}
}

type Registry struct {
	mu       sync.RWMutex
	services map[string]*Service
}

func NewRegistry() *Registry {
	return &Registry{services: map[string]*Service{}}
}

func (r *Registry) Service(key string) *Service {
	if r == nil {
		return nil
	}
	k := strings.TrimSpace(key)
	if k == "" {
		return nil
	}

	r.mu.RLock()
	s := r.services[k]
	r.mu.RUnlock()
	if s != nil {
		return s
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if s := r.services[k]; s != nil {
		return s
	}
	s = &Service{key: k}
	r.services[k] = s
	return s
}

func (r *Registry) Snapshot() map[string]Snapshot {
	if r == nil {
		return map[string]Snapshot{}
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make(map[string]Snapshot, len(r.services))
	for k, svc := range r.services {
		out[k] = svc.Snapshot()
	}
	return out
}

func Wrap(svc *Service, next http.Handler) http.Handler {
	if next == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	}
	if svc == nil {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Avoid polluting traffic stats with internal admin probes.
		if r != nil {
			p := r.URL.Path
			if strings.HasPrefix(p, "/_hazuki/") {
				next.ServeHTTP(w, r)
				return
			}
		}

		svc.requests.Add(1)

		var bodyCounter *countingReadCloser
		if r != nil && r.Body != nil {
			bodyCounter = &countingReadCloser{ReadCloser: r.Body, svc: svc}
			r.Body = bodyCounter
		}

		crw := &countingResponseWriter{ResponseWriter: w, svc: svc}
		next.ServeHTTP(crw, r)
	})
}

type countingReadCloser struct {
	io.ReadCloser
	svc *Service
	n int64
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	if n > 0 {
		c.n += int64(n)
		if c.svc != nil {
			c.svc.bytesIn.Add(int64(n))
		}
	}
	return n, err
}

const copyBufSize = 32 * 1024

var copyBufPool = sync.Pool{New: func() any { return make([]byte, copyBufSize) }}

type countingResponseWriter struct {
	http.ResponseWriter
	svc *Service
	n int64
}

func (w *countingResponseWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	if n > 0 {
		w.n += int64(n)
		if w.svc != nil {
			w.svc.bytesOut.Add(int64(n))
		}
	}
	return n, err
}

func (w *countingResponseWriter) ReadFrom(r io.Reader) (int64, error) {
	if r == nil {
		return 0, nil
	}
	buf := copyBufPool.Get().([]byte)
	defer copyBufPool.Put(buf)

	var total int64
	for {
		nr, er := r.Read(buf)
		if nr > 0 {
			nw, ew := w.ResponseWriter.Write(buf[:nr])
			if nw > 0 {
				total += int64(nw)
				w.n += int64(nw)
				if w.svc != nil {
					w.svc.bytesOut.Add(int64(nw))
				}
			}
			if ew != nil {
				return total, ew
			}
			if nw != nr {
				return total, io.ErrShortWrite
			}
		}
		if er != nil {
			if er == io.EOF {
				return total, nil
			}
			return total, er
		}
	}
}

func (w *countingResponseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *countingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return h.Hijack()
}

func (w *countingResponseWriter) Push(target string, opts *http.PushOptions) error {
	p, ok := w.ResponseWriter.(http.Pusher)
	if !ok {
		return http.ErrNotSupported
	}
	return p.Push(target, opts)
}
