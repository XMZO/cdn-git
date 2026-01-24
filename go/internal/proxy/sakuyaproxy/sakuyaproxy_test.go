package sakuyaproxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestVerifySign(t *testing.T) {
	token := "test-token"
	path := "/foo/bar"

	now := time.Unix(2000, 0).UTC()
	expire := int64(3000)
	sign := hmacSha256Sign(path, expire, token)

	if msg := verifySign(path, sign, token, now); msg != "" {
		t.Fatalf("verifySign should pass, got: %q", msg)
	}

	if msg := verifySign(path, "", token, now); msg != "expire missing" {
		t.Fatalf("empty sign: got %q", msg)
	}
	if msg := verifySign(path, "abc:", token, now); msg != "expire missing" {
		t.Fatalf("missing expire: got %q", msg)
	}
	if msg := verifySign(path, "abc", token, now); msg != "expire invalid" {
		t.Fatalf("invalid expire: got %q", msg)
	}

	expiredSign := hmacSha256Sign(path, 100, token)
	if msg := verifySign(path, expiredSign, token, now); msg != "expire expired" {
		t.Fatalf("expired: got %q", msg)
	}

	bad := hmacSha256Sign(path, expire, "wrong-token")
	if msg := verifySign(path, bad, token, now); msg != "sign mismatch" {
		t.Fatalf("mismatch: got %q", msg)
	}
}

func TestFetchLink_RetryAndCache(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/fs/link" {
			http.NotFound(w, r)
			return
		}

		n := atomic.AddInt32(&calls, 1)
		w.Header().Set("content-type", "application/json; charset=utf-8")
		if n == 1 {
			_, _ = io.WriteString(w, `{"code":500,"message":"failed link: failed get link: context canceled","data":{"url":""}}`)
			return
		}
		_, _ = io.WriteString(w, `{"code":200,"message":"","data":{"url":"https://example.com/file","header":{}}}`)
	}))
	t.Cleanup(srv.Close)

	h := NewHandler(HandlerOptions{
		APIClient:      srv.Client(),
		LinkTimeout:    2 * time.Second,
		LinkRetries:    1,
		LinkCacheTTL:   2 * time.Second,
		MaxRedirects:   1,
		DownloadClient: &http.Client{Transport: http.DefaultTransport},
	})

	runtime := RuntimeConfig{
		OplistAddress: srv.URL,
		OplistToken:   "test-token",
	}

	got, err := h.fetchLinkCached(context.Background(), runtime, "/a/b")
	if err != nil {
		t.Fatalf("fetchLinkCached: %v", err)
	}
	if got.Code != 200 || got.Data.URL == "" {
		t.Fatalf("unexpected response: code=%d url=%q", got.Code, got.Data.URL)
	}
	if atomic.LoadInt32(&calls) != 2 {
		t.Fatalf("expected 2 calls (1 retry), got %d", calls)
	}

	got2, err := h.fetchLinkCached(context.Background(), runtime, "/a/b")
	if err != nil {
		t.Fatalf("fetchLinkCached (cached): %v", err)
	}
	if got2.Code != 200 || got2.Data.URL == "" {
		t.Fatalf("unexpected cached response: code=%d url=%q", got2.Code, got2.Data.URL)
	}
	if atomic.LoadInt32(&calls) != 2 {
		t.Fatalf("expected cached result without extra calls, got %d", calls)
	}
}
