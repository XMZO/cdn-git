package torcherinoproxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
)

func TestTorcherinoForwardClientIP_Disabled(t *testing.T) {
	var mu sync.Mutex
	var gotXHazukiClientIP string
	var gotXRealIP string
	var gotXForwardedFor string

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotXHazukiClientIP = r.Header.Get("X-Hazuki-Client-IP")
		gotXRealIP = r.Header.Get("X-Real-IP")
		gotXForwardedFor = r.Header.Get("X-Forwarded-For")
		mu.Unlock()

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	runtime := RuntimeConfig{
		DefaultTarget:   u.Host,
		ForwardClientIP: false,
	}

	req := httptest.NewRequest(http.MethodGet, "http://hazuki.example/test", nil)
	req.RemoteAddr = "1.2.3.4:5678"
	req.Header.Set("Cf-Connecting-Ip", "9.8.7.6")

	rr := httptest.NewRecorder()
	handleRequest(rr, req, runtime, ts.Client(), nil)

	mu.Lock()
	defer mu.Unlock()
	if gotXHazukiClientIP != "" {
		t.Fatalf("expected X-Hazuki-Client-IP to be empty, got %q", gotXHazukiClientIP)
	}
	if gotXRealIP != "" {
		t.Fatalf("expected X-Real-IP to be empty, got %q", gotXRealIP)
	}
	if gotXForwardedFor != "" {
		t.Fatalf("expected X-Forwarded-For to be empty, got %q", gotXForwardedFor)
	}
}

func TestTorcherinoForwardClientIP_InjectsHeaders(t *testing.T) {
	var mu sync.Mutex
	var gotXHazukiClientIP string
	var gotXRealIP string
	var gotXForwardedFor string

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotXHazukiClientIP = r.Header.Get("X-Hazuki-Client-IP")
		gotXRealIP = r.Header.Get("X-Real-IP")
		gotXForwardedFor = r.Header.Get("X-Forwarded-For")
		mu.Unlock()

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	runtime := RuntimeConfig{
		DefaultTarget:   u.Host,
		ForwardClientIP: true,
	}

	req := httptest.NewRequest(http.MethodGet, "http://hazuki.example/test", nil)
	req.RemoteAddr = "1.2.3.4:5678"
	req.Header.Set("Cf-Connecting-Ip", "9.8.7.6")

	rr := httptest.NewRecorder()
	handleRequest(rr, req, runtime, ts.Client(), nil)

	mu.Lock()
	defer mu.Unlock()
	if gotXHazukiClientIP != "9.8.7.6" {
		t.Fatalf("expected X-Hazuki-Client-IP %q, got %q", "9.8.7.6", gotXHazukiClientIP)
	}
	if gotXRealIP != "9.8.7.6" {
		t.Fatalf("expected X-Real-IP %q, got %q", "9.8.7.6", gotXRealIP)
	}
	if gotXForwardedFor != "9.8.7.6" {
		t.Fatalf("expected X-Forwarded-For %q, got %q", "9.8.7.6", gotXForwardedFor)
	}
}

func TestTorcherinoForwardClientIP_DoesNotOverrideXForwardedFor(t *testing.T) {
	var mu sync.Mutex
	var gotXHazukiClientIP string
	var gotXRealIP string
	var gotXForwardedFor string

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotXHazukiClientIP = r.Header.Get("X-Hazuki-Client-IP")
		gotXRealIP = r.Header.Get("X-Real-IP")
		gotXForwardedFor = r.Header.Get("X-Forwarded-For")
		mu.Unlock()

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	runtime := RuntimeConfig{
		DefaultTarget:   u.Host,
		ForwardClientIP: true,
	}

	req := httptest.NewRequest(http.MethodGet, "http://hazuki.example/test", nil)
	req.RemoteAddr = "1.2.3.4:5678"
	req.Header.Set("Cf-Connecting-Ip", "9.8.7.6")
	req.Header.Set("X-Forwarded-For", "11.11.11.11, 22.22.22.22")

	rr := httptest.NewRecorder()
	handleRequest(rr, req, runtime, ts.Client(), nil)

	mu.Lock()
	defer mu.Unlock()
	if gotXHazukiClientIP != "9.8.7.6" {
		t.Fatalf("expected X-Hazuki-Client-IP %q, got %q", "9.8.7.6", gotXHazukiClientIP)
	}
	if gotXRealIP != "11.11.11.11" {
		t.Fatalf("expected X-Real-IP %q, got %q", "11.11.11.11", gotXRealIP)
	}
	if gotXForwardedFor != "11.11.11.11, 22.22.22.22" {
		t.Fatalf("expected X-Forwarded-For to be preserved, got %q", gotXForwardedFor)
	}
}

func TestTorcherinoForwardClientIP_TrustCfConnectingIP(t *testing.T) {
	var mu sync.Mutex
	var gotXHazukiClientIP string
	var gotXRealIP string
	var gotXForwardedFor string

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotXHazukiClientIP = r.Header.Get("X-Hazuki-Client-IP")
		gotXRealIP = r.Header.Get("X-Real-IP")
		gotXForwardedFor = r.Header.Get("X-Forwarded-For")
		mu.Unlock()

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	runtime := RuntimeConfig{
		DefaultTarget:       u.Host,
		ForwardClientIP:     true,
		TrustCfConnectingIP: true,
	}

	req := httptest.NewRequest(http.MethodGet, "http://hazuki.example/test", nil)
	req.RemoteAddr = "1.2.3.4:5678"
	req.Header.Set("Cf-Connecting-Ip", "9.8.7.6")
	req.Header.Set("X-Forwarded-For", "11.11.11.11, 22.22.22.22")

	rr := httptest.NewRecorder()
	handleRequest(rr, req, runtime, ts.Client(), nil)

	mu.Lock()
	defer mu.Unlock()
	if gotXHazukiClientIP != "9.8.7.6" {
		t.Fatalf("expected X-Hazuki-Client-IP %q, got %q", "9.8.7.6", gotXHazukiClientIP)
	}
	if gotXRealIP != "9.8.7.6" {
		t.Fatalf("expected X-Real-IP %q, got %q", "9.8.7.6", gotXRealIP)
	}
	if gotXForwardedFor != "11.11.11.11, 22.22.22.22" {
		t.Fatalf("expected X-Forwarded-For to be preserved, got %q", gotXForwardedFor)
	}
}

func TestTorcherinoForwardClientIP_TrustedHazukiClientIP(t *testing.T) {
	var mu sync.Mutex
	var gotXHazukiClientIP string
	var gotXRealIP string
	var gotXForwardedFor string

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotXHazukiClientIP = r.Header.Get("X-Hazuki-Client-IP")
		gotXRealIP = r.Header.Get("X-Real-IP")
		gotXForwardedFor = r.Header.Get("X-Forwarded-For")
		mu.Unlock()

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	runtime := RuntimeConfig{
		DefaultTarget:       u.Host,
		ForwardClientIP:     true,
		WorkerSecretKey:     "secret",
		WorkerSecretHeaders: []string{"x-forwarded-by-worker"},
	}

	req := httptest.NewRequest(http.MethodGet, "http://hazuki.example/test", nil)
	req.RemoteAddr = "1.2.3.4:5678"
	req.Header.Set("X-Forwarded-By-Worker", "secret")
	req.Header.Set("X-Hazuki-Client-IP", "55.66.77.88")
	req.Header.Set("X-Forwarded-For", "11.11.11.11, 22.22.22.22")

	rr := httptest.NewRecorder()
	handleRequest(rr, req, runtime, ts.Client(), nil)

	mu.Lock()
	defer mu.Unlock()
	if gotXHazukiClientIP != "55.66.77.88" {
		t.Fatalf("expected X-Hazuki-Client-IP %q, got %q", "55.66.77.88", gotXHazukiClientIP)
	}
	if gotXRealIP != "55.66.77.88" {
		t.Fatalf("expected X-Real-IP %q, got %q", "55.66.77.88", gotXRealIP)
	}
	if gotXForwardedFor != "11.11.11.11, 22.22.22.22" {
		t.Fatalf("expected X-Forwarded-For to be preserved, got %q", gotXForwardedFor)
	}
}
