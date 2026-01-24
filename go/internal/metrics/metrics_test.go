package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWrap_BytesOutUpdatesDuringHandler(t *testing.T) {
	reg := NewRegistry()
	svc := reg.Service("svc")

	gotCh := make(chan int64, 1)

	h := Wrap(svc, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello"))
		gotCh <- svc.Snapshot().BytesOut
	}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	h.ServeHTTP(rr, req)

	select {
	case got := <-gotCh:
		if got != int64(len("hello")) {
			t.Fatalf("bytesOut during handler = %d, want %d", got, len("hello"))
		}
	default:
		t.Fatalf("handler did not report bytesOut")
	}
}

type blockingReader struct {
	first            []byte
	second           []byte
	secondReadStarted chan struct{}
	continueCh       chan struct{}
	calls            int
}

func (r *blockingReader) Read(p []byte) (int, error) {
	r.calls++
	switch r.calls {
	case 1:
		return copy(p, r.first), nil
	case 2:
		close(r.secondReadStarted)
		<-r.continueCh
		n := copy(p, r.second)
		return n, io.EOF
	default:
		return 0, io.EOF
	}
}

func TestWrap_BytesOutUpdatesDuringStreaming(t *testing.T) {
	reg := NewRegistry()
	svc := reg.Service("svc")

	r := &blockingReader{
		first:             []byte("abc"),
		second:            []byte("defg"),
		secondReadStarted: make(chan struct{}),
		continueCh:        make(chan struct{}),
	}

	h := Wrap(svc, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.Copy(w, r)
	}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)

	done := make(chan struct{})
	go func() {
		h.ServeHTTP(rr, req)
		close(done)
	}()

	select {
	case <-r.secondReadStarted:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for streaming to reach second read")
	}

	gotMid := svc.Snapshot().BytesOut
	if gotMid != int64(len(r.first)) {
		t.Fatalf("bytesOut mid-stream = %d, want %d", gotMid, len(r.first))
	}

	close(r.continueCh)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for handler to finish")
	}

	gotFinal := svc.Snapshot().BytesOut
	wantFinal := int64(len(r.first) + len(r.second))
	if gotFinal != wantFinal {
		t.Fatalf("bytesOut final = %d, want %d", gotFinal, wantFinal)
	}
}

func TestWrap_BytesInUpdatesDuringHandler(t *testing.T) {
	reg := NewRegistry()
	svc := reg.Service("svc")

	gotCh := make(chan int64, 1)

	h := Wrap(svc, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 2)
		_, _ = io.ReadFull(r.Body, buf)
		gotCh <- svc.Snapshot().BytesIn
		_, _ = w.Write([]byte("ok"))
	}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://example.com/", io.NopCloser(strings.NewReader("hello")))
	h.ServeHTTP(rr, req)

	select {
	case got := <-gotCh:
		if got != 2 {
			t.Fatalf("bytesIn during handler = %d, want %d", got, 2)
		}
	default:
		t.Fatalf("handler did not report bytesIn")
	}
}

