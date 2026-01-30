package patchouliproxy

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"hazuki-go/internal/model"
	"hazuki-go/internal/proxy/upstreamhttp"
)

type RuntimeConfig struct {
	Host string
	Port int

	Disabled bool

	// dataset | model | space
	Kind string

	Repo     string
	Revision string

	// HuggingFace access token (hf_...). Used as "Authorization: Bearer <token>".
	Token string

	// Optional access key gate. If set, clients must provide it via query (?key=) or header (X-Patchouli-Key).
	AccessKey string

	DisableCache bool

	AllowedRedirectHostSuffixes []string
	MaxRedirects                int
}

func BuildRuntimeConfig(cfg model.AppConfig) (RuntimeConfig, error) {
	port := cfg.Ports.Patchouli
	if port == 0 {
		port = 3201
	}

	kind := strings.ToLower(strings.TrimSpace(cfg.Patchouli.Kind))
	if kind == "" {
		kind = "dataset"
	}
	switch kind {
	case "dataset", "model", "space":
	default:
		return RuntimeConfig{}, errors.New("patchouli.kind must be 'dataset', 'model' or 'space'")
	}

	repo := strings.TrimSpace(cfg.Patchouli.Repo)
	rev := strings.TrimSpace(cfg.Patchouli.Revision)
	if rev == "" {
		rev = "main"
	}

	allowedSuffixes := trimLower(cfg.Patchouli.AllowedRedirectHostSuffixes)
	if len(allowedSuffixes) == 0 {
		allowedSuffixes = []string{".huggingface.co", ".hf.co", ".cloudfront.net", ".amazonaws.com"}
	}

	disabled := cfg.Patchouli.Disabled || repo == ""

	return RuntimeConfig{
		Host: "0.0.0.0",
		Port: port,

		Disabled: disabled,
		Kind:     kind,
		Repo:     repo,
		Revision: rev,
		Token:    cfg.Patchouli.Token,

		AccessKey:    strings.TrimSpace(cfg.Patchouli.AccessKey),
		DisableCache: cfg.Patchouli.DisableCache,

		AllowedRedirectHostSuffixes: allowedSuffixes,
		MaxRedirects:                10,
	}, nil
}

func NewHandler(runtime RuntimeConfig) http.Handler {
	return NewDynamicHandler(func() RuntimeConfig { return runtime })
}

func NewDynamicHandler(getRuntime func() RuntimeConfig) http.Handler {
	client := upstreamhttp.NewClient(upstreamhttp.Options{FollowRedirects: false})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		runtime := RuntimeConfig{}
		if getRuntime != nil {
			runtime = getRuntime()
		}
		handleRequest(w, r, runtime, client)
	})
}

func handleRequest(w http.ResponseWriter, r *http.Request, runtime RuntimeConfig, client *http.Client) {
	if (r.Method == http.MethodGet || r.Method == http.MethodHead) && r.URL.Path == "/_hazuki/health" {
		if !isLoopbackRemoteAddr(r.RemoteAddr) {
			http.NotFound(w, r)
			return
		}

		payload := map[string]any{
			"ok":        true,
			"service":   "patchouli",
			"host":      runtime.Host,
			"port":      runtime.Port,
			"disabled":  runtime.Disabled,
			"kind":      runtime.Kind,
			"repoSet":   strings.TrimSpace(runtime.Repo) != "",
			"revision":  runtime.Revision,
			"tokenSet":  strings.TrimSpace(runtime.Token) != "",
			"accessKey": strings.TrimSpace(runtime.AccessKey) != "",
			"time":      time.Now().UTC().Format(time.RFC3339Nano),
		}
		buf, _ := json.MarshalIndent(payload, "", "  ")
		w.Header().Set("content-type", "application/json; charset=utf-8")
		w.Header().Set("cache-control", "no-store")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(buf)
		return
	}

	if r.Method == http.MethodOptions {
		applyCorsHeaders(w.Header())
		w.Header().Set("access-control-allow-methods", "GET,HEAD,OPTIONS")
		reqHeaders := strings.TrimSpace(r.Header.Get("Access-Control-Request-Headers"))
		if reqHeaders == "" {
			reqHeaders = "Range"
		}
		w.Header().Set("access-control-allow-headers", reqHeaders)
		w.Header().Set("access-control-max-age", "86400")
		w.Header().Set("cache-control", "no-store")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	switch r.Method {
	case http.MethodGet, http.MethodHead:
		// continue
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if runtime.Disabled {
		http.NotFound(w, r)
		return
	}

	if runtime.AccessKey != "" && !checkAccessKey(r, runtime.AccessKey) {
		w.Header().Set("content-type", "text/plain; charset=utf-8")
		w.Header().Set("cache-control", "no-store")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("Forbidden"))
		return
	}

	pathname := strings.TrimPrefix(r.URL.Path, "/")
	pathname = strings.Trim(pathname, "/")
	if pathname == "" || strings.HasPrefix(pathname, "_hazuki/") {
		http.NotFound(w, r)
		return
	}
	if !isSafeRelativePath(pathname) {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	upstreamURL := buildFileURL(runtime.Kind, runtime.Repo, runtime.Revision, pathname, sanitizeUpstreamQuery(r.URL.Query()))
	if upstreamURL == "" {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	upstreamReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, nil)
	if err != nil {
		http.Error(w, "Bad gateway", http.StatusBadGateway)
		return
	}
	upstreamReq.Header = buildUpstreamRequestHeaders(r, runtime.Token)
	upstreamReq.Host = upstreamReq.URL.Host

	resp, err := doWithRedirects(client, upstreamReq, runtime)
	if err != nil {
		http.Error(w, "Bad gateway", http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	copyResponseHeaders(w.Header(), resp.Header)
	applyCorsHeaders(w.Header())
	w.Header().Set("accept-ranges", "bytes")
	w.Header().Set("vary", "Range")

	if shouldNoStore(runtime, resp) {
		w.Header().Set("cache-control", "no-store")
	}

	w.WriteHeader(resp.StatusCode)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = io.Copy(w, resp.Body)
}

func shouldNoStore(runtime RuntimeConfig, resp *http.Response) bool {
	if runtime.DisableCache {
		return true
	}
	if strings.TrimSpace(runtime.Token) != "" {
		return true
	}
	if strings.TrimSpace(runtime.AccessKey) != "" {
		// If access is gated, avoid caching by shared CDNs.
		return true
	}
	// Respect upstream explicit no-store/private.
	cc := strings.ToLower(strings.TrimSpace(resp.Header.Get("cache-control")))
	return strings.Contains(cc, "no-store") || strings.Contains(cc, "private")
}

func applyCorsHeaders(headers http.Header) {
	headers.Set("access-control-allow-origin", "*")
	headers.Set("access-control-expose-headers", "Accept-Ranges, Content-Length, Content-Range, ETag, Cache-Control, Last-Modified")
}

func checkAccessKey(r *http.Request, expected string) bool {
	exp := strings.TrimSpace(expected)
	if exp == "" || r == nil {
		return false
	}
	if got := strings.TrimSpace(r.Header.Get("X-Patchouli-Key")); got != "" {
		return got == exp
	}
	if q := strings.TrimSpace(r.URL.Query().Get("key")); q != "" {
		return q == exp
	}
	return false
}

func buildFileURL(kind, repo, revision, filePath, rawQuery string) string {
	repo = strings.TrimSpace(repo)
	if repo == "" {
		return ""
	}
	revision = strings.TrimSpace(revision)
	if revision == "" {
		revision = "main"
	}
	filePath = strings.Trim(filePath, "/")

	prefix := ""
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "dataset":
		prefix = "/datasets"
	case "space":
		prefix = "/spaces"
	case "model":
		prefix = ""
	default:
		return ""
	}

	u := &url.URL{
		Scheme:   "https",
		Host:     "huggingface.co",
		Path:     prefix + "/" + repo + "/resolve/" + revision + "/" + filePath,
		RawQuery: rawQuery,
	}
	return u.String()
}

func isSafeRelativePath(p string) bool {
	p = strings.Trim(p, "/")
	if strings.TrimSpace(p) == "" {
		return false
	}
	if strings.Contains(p, "\\") {
		return false
	}
	if strings.Contains(p, "\x00") {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		switch seg {
		case "", ".", "..":
			return false
		}
	}
	return true
}

func buildUpstreamRequestHeaders(r *http.Request, token string) http.Header {
	headers := make(http.Header)
	if r != nil {
		for key, values := range r.Header {
			lowerKey := strings.ToLower(key)
			if shouldSkipUpstreamHeader(lowerKey) {
				continue
			}
			for _, v := range values {
				headers.Add(lowerKey, v)
			}
		}
	}

	// Avoid gzip/br to reduce CPU and preserve byte-accurate Range semantics.
	headers.Set("accept-encoding", "identity")

	if strings.TrimSpace(token) != "" {
		headers.Set("authorization", "Bearer "+strings.TrimSpace(token))
	}

	return headers
}

func shouldSkipUpstreamHeader(lowerKey string) bool {
	switch lowerKey {
	case "connection",
		"keep-alive",
		"proxy-authenticate",
		"proxy-authorization",
		"authorization",
		"cookie",
		"x-patchouli-key",
		"x-forwarded-for",
		"x-real-ip",
		"cf-connecting-ip",
		"te",
		"trailer",
		"transfer-encoding",
		"upgrade",
		"host",
		"accept-encoding",
		"content-length":
		return true
	default:
		return false
	}
}

func copyResponseHeaders(dst, src http.Header) {
	for key, values := range src {
		lowerKey := strings.ToLower(key)
		if shouldSkipClientHeader(lowerKey) {
			continue
		}
		for _, v := range values {
			dst.Add(lowerKey, v)
		}
	}
}

func shouldSkipClientHeader(lowerKey string) bool {
	switch lowerKey {
	case "content-security-policy",
		"content-security-policy-report-only",
		"clear-site-data",
		"content-encoding",
		"connection",
		"keep-alive",
		"proxy-authenticate",
		"proxy-authorization",
		"set-cookie",
		"te",
		"trailer",
		"transfer-encoding",
		"upgrade":
		return true
	default:
		return false
	}
}

func doWithRedirects(client *http.Client, req *http.Request, runtime RuntimeConfig) (*http.Response, error) {
	if client == nil || req == nil {
		return nil, errors.New("nil request")
	}

	max := runtime.MaxRedirects
	if max <= 0 {
		max = 10
	}

	baseOrigin := originKey(req.URL)
	curReq := req
	for i := 0; i <= max; i++ {
		resp, err := client.Do(curReq)
		if err != nil {
			return nil, err
		}

		if !isRedirectStatus(resp.StatusCode) {
			return resp, nil
		}

		loc := strings.TrimSpace(resp.Header.Get("location"))
		_ = resp.Body.Close()
		if loc == "" {
			return nil, errors.New("redirect without location")
		}

		nextURL, err := curReq.URL.Parse(loc)
		if err != nil {
			return nil, err
		}
		if !isAllowedRedirect(nextURL, runtime.AllowedRedirectHostSuffixes) {
			return nil, errors.New("redirect blocked")
		}

		nextReq, err := http.NewRequestWithContext(req.Context(), req.Method, nextURL.String(), nil)
		if err != nil {
			return nil, err
		}
		nextReq.Header = cloneHeader(curReq.Header)
		nextReq.Host = nextURL.Host

		if nextOrigin := originKey(nextURL); nextOrigin != "" && baseOrigin != "" && nextOrigin != baseOrigin {
			nextReq.Header.Del("authorization")
		}

		curReq = nextReq
	}
	return nil, errors.New("too many redirects")
}

func originKey(u *url.URL) string {
	if u == nil {
		return ""
	}
	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if host == "" {
		return ""
	}
	port := strings.TrimSpace(u.Port())
	if port == "" {
		switch strings.ToLower(strings.TrimSpace(u.Scheme)) {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return host + ":" + port
}

func sanitizeUpstreamQuery(in url.Values) string {
	if in == nil {
		return ""
	}
	out := make(url.Values, len(in))
	for k, vals := range in {
		if vals == nil {
			continue
		}
		cp := append([]string(nil), vals...)
		out[k] = cp
	}
	out.Del("key")
	return out.Encode()
}

func isRedirectStatus(code int) bool {
	switch code {
	case http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusSeeOther,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

func isAllowedRedirect(u *url.URL, allowedSuffixes []string) bool {
	if u == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(u.Scheme)) {
	case "https", "http":
		// ok
	default:
		return false
	}
	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if host == "" {
		return false
	}

	for _, s := range allowedSuffixes {
		suf := strings.ToLower(strings.TrimSpace(s))
		if suf == "" {
			continue
		}
		if host == suf || strings.HasSuffix(host, suf) {
			return true
		}
	}
	return false
}

func cloneHeader(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, vals := range h {
		if vals == nil {
			continue
		}
		cp := append([]string(nil), vals...)
		out[k] = cp
	}
	return out
}

func trimLower(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		s := strings.ToLower(strings.TrimSpace(raw))
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func isLoopbackRemoteAddr(addr string) bool {
	host := strings.TrimSpace(addr)
	if host == "" {
		return false
	}
	if h, _, err := net.SplitHostPort(host); err == nil && strings.TrimSpace(h) != "" {
		host = h
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
