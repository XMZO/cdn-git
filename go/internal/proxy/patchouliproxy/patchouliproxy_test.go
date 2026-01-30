package patchouliproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"hazuki-go/internal/proxy/upstreamhttp"
)

func TestSanitizeUpstreamQuery_RemovesKeyWithoutMutatingInput(t *testing.T) {
	in := url.Values{
		"download": []string{"true"},
		"key":      []string{"secret"},
		"multi":    []string{"a", "b"},
	}

	got := sanitizeUpstreamQuery(in)

	if in.Get("key") != "secret" {
		t.Fatalf("expected input query to remain unchanged, got key=%q", in.Get("key"))
	}

	out, err := url.ParseQuery(got)
	if err != nil {
		t.Fatalf("ParseQuery failed: %v", err)
	}
	if out.Get("key") != "" {
		t.Fatalf("expected key to be removed, got %q", out.Get("key"))
	}
	if out.Get("download") != "true" {
		t.Fatalf("expected download=true, got %q", out.Get("download"))
	}
	if strings.Join(out["multi"], ",") != "a,b" {
		t.Fatalf("expected multi=a,b, got %v", out["multi"])
	}
}

func TestIsSafeRelativePath(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"file.bin", true},
		{"dir/file.bin", true},
		{"a..b/file.bin", true},
		{"/dir/file.bin/", true},
		{"", false},
		{"..", false},
		{"../file.bin", false},
		{"dir/../file.bin", false},
		{"dir//file.bin", false},
		{"dir\\file.bin", false},
		{"dir/\x00file.bin", false},
	}
	for _, tc := range cases {
		if got := isSafeRelativePath(tc.in); got != tc.want {
			t.Fatalf("isSafeRelativePath(%q)=%v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestBuildUpstreamRequestHeaders_SkipsClientSecrets(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://example.com/file.bin?key=secret", nil)
	r.Header.Set("Authorization", "Bearer should-not-forward")
	r.Header.Set("Cookie", "a=b")
	r.Header.Set("X-Patchouli-Key", "secret")
	r.Header.Set("Range", "bytes=0-99")

	h := buildUpstreamRequestHeaders(r, "hf_token")

	if got := h.Get("Authorization"); got != "Bearer hf_token" {
		t.Fatalf("expected Authorization to be our token, got %q", got)
	}
	if got := h.Get("Cookie"); got != "" {
		t.Fatalf("expected Cookie to be stripped, got %q", got)
	}
	if got := h.Get("X-Patchouli-Key"); got != "" {
		t.Fatalf("expected X-Patchouli-Key to be stripped, got %q", got)
	}
	if got := h.Get("Range"); got != "bytes=0-99" {
		t.Fatalf("expected Range to be forwarded, got %q", got)
	}
	if got := h.Get("Accept-Encoding"); got != "identity" {
		t.Fatalf("expected Accept-Encoding=identity, got %q", got)
	}
}

func TestDoWithRedirects_DropsAuthorizationOnCrossOriginRedirect(t *testing.T) {
	var sawAuth atomic.Bool

	dst := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.TrimSpace(r.Header.Get("Authorization")) != "" {
			sawAuth.Store(true)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(dst.Close)

	dstURL, err := url.Parse(dst.URL)
	if err != nil {
		t.Fatalf("parse dst url: %v", err)
	}
	dstURL.Host = "localhost:" + dstURL.Port()

	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", dstURL.String())
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(src.Close)

	req, err := http.NewRequest(http.MethodGet, src.URL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer hf_token")

	client := upstreamhttp.NewClient(upstreamhttp.Options{FollowRedirects: false})
	resp, err := doWithRedirects(client, req, RuntimeConfig{
		AllowedRedirectHostSuffixes: []string{"127.0.0.1", "localhost"},
		MaxRedirects:                5,
	})
	if err != nil {
		t.Fatalf("doWithRedirects: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}
	if sawAuth.Load() {
		t.Fatalf("expected Authorization to be dropped on cross-origin redirect")
	}
}
