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
			bodyCounter = &countingReadCloser{ReadCloser: r.Body}
			r.Body = bodyCounter
		}

		crw := &countingResponseWriter{ResponseWriter: w}
		next.ServeHTTP(crw, r)

		if bodyCounter != nil {
			svc.bytesIn.Add(bodyCounter.n)
		}
		svc.bytesOut.Add(crw.n)
	})
}

type countingReadCloser struct {
	io.ReadCloser
	n int64
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	c.n += int64(n)
	return n, err
}

type countingResponseWriter struct {
	http.ResponseWriter
	n int64
}

func (w *countingResponseWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	w.n += int64(n)
	return n, err
}

func (w *countingResponseWriter) ReadFrom(r io.Reader) (int64, error) {
	if rf, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		n, err := rf.ReadFrom(r)
		w.n += n
		return n, err
	}
	n, err := io.Copy(w.ResponseWriter, r)
	w.n += n
	return n, err
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
