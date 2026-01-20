package gitproxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"hazuki-go/internal/model"
)

type CorsOrigins struct {
	Kind      string
	AllowList map[string]struct{}
}

type RuntimeConfig struct {
	Upstream       string
	UpstreamMobile string
	UpstreamPath   string
	HTTPS          bool

	GithubToken      string
	GithubAuthScheme string

	DisableCache      bool
	CacheControl      string
	CacheControlMedia string
	CacheControlText  string

	CorsOrigins          CorsOrigins
	CorsAllowCredentials bool
	CorsExposeHeaders    string

	BlockedRegions     map[string]struct{}
	BlockedIPAddresses map[string]struct{}

	ReplaceDict map[string]string

	Host string
	Port int
}

func BuildRuntimeConfig(cfg model.AppConfig) (RuntimeConfig, error) {
	upstream := strings.TrimSpace(cfg.Git.Upstream)
	if upstream == "" {
		upstream = "raw.githubusercontent.com"
	}
	upstreamMobile := strings.TrimSpace(cfg.Git.UpstreamMobile)
	if upstreamMobile == "" {
		upstreamMobile = upstream
	}

	upstreamPath := normalizeUpstreamPath(cfg.Git.UpstreamPath)
	if upstreamPath == "" && strings.TrimSpace(cfg.Git.UpstreamPath) != "/" {
		// normalizeUpstreamPath("/") becomes "", which is valid (means "no prefix").
		// For other empty-ish values, fail fast.
		return RuntimeConfig{}, errors.New("git.upstreamPath is required")
	}

	replaceDict := cfg.Git.ReplaceDict
	if replaceDict == nil {
		replaceDict = map[string]string{"$upstream": "$custom_domain"}
	}

	blockedRegions := make(map[string]struct{}, len(cfg.Git.BlockedRegions))
	for _, r := range cfg.Git.BlockedRegions {
		rr := strings.ToUpper(strings.TrimSpace(r))
		if rr == "" {
			continue
		}
		blockedRegions[rr] = struct{}{}
	}
	blockedIPs := make(map[string]struct{}, len(cfg.Git.BlockedIpAddresses))
	for _, ip := range cfg.Git.BlockedIpAddresses {
		s := strings.TrimSpace(ip)
		if s == "" {
			continue
		}
		blockedIPs[s] = struct{}{}
	}

	corsOrigins := parseCorsOrigins(cfg.Git.CorsOrigin)
	corsAllowCreds := cfg.Git.CorsAllowCredentials
	if corsAllowCreds && corsOrigins.Kind == "any" {
		// Same as Node: credentials + "*" is invalid; disable credentials.
		corsAllowCreds = false
	}

	port := cfg.Ports.Git
	if port == 0 {
		port = 3002
	}

	return RuntimeConfig{
		Upstream:       upstream,
		UpstreamMobile: upstreamMobile,
		UpstreamPath:   upstreamPath,
		HTTPS:          cfg.Git.HTTPS,

		GithubToken:      cfg.Git.GithubToken,
		GithubAuthScheme: strings.TrimSpace(defaultString(cfg.Git.GithubAuthScheme, "token")),

		DisableCache:      cfg.Git.DisableCache,
		CacheControl:      strings.TrimSpace(cfg.Git.CacheControl),
		CacheControlMedia: strings.TrimSpace(defaultString(cfg.Git.CacheControlMedia, "public, max-age=43200000")),
		CacheControlText:  strings.TrimSpace(defaultString(cfg.Git.CacheControlText, "public, max-age=60")),

		CorsOrigins:          corsOrigins,
		CorsAllowCredentials: corsAllowCreds,
		CorsExposeHeaders:    strings.TrimSpace(cfg.Git.CorsExposeHeaders),

		BlockedRegions:     blockedRegions,
		BlockedIPAddresses: blockedIPs,

		ReplaceDict: replaceDict,

		Host: "0.0.0.0",
		Port: port,
	}, nil
}

func NewHandler(runtime RuntimeConfig) http.Handler {
	return NewDynamicHandler(func() RuntimeConfig { return runtime })
}

func NewDynamicHandler(getRuntime func() RuntimeConfig) http.Handler {
	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		runtime := RuntimeConfig{}
		if getRuntime != nil {
			runtime = getRuntime()
		}
		handleRequest(w, r, runtime, client)
	})
}

func handleRequest(w http.ResponseWriter, r *http.Request, runtime RuntimeConfig, client *http.Client) {
	originalHost := getOriginalHost(r)
	originalProto := getOriginalProto(r)
	requestOrigin := r.Header.Get("Origin")

	if (r.Method == http.MethodGet || r.Method == http.MethodHead) && r.URL.Path == "/_hazuki/health" {
		payload := map[string]any{
			"ok":            true,
			"service":       "git",
			"host":          runtime.Host,
			"port":          runtime.Port,
			"upstream":      runtime.Upstream,
			"upstreamMobile": runtime.UpstreamMobile,
			"upstreamPath":  runtime.UpstreamPath,
			"https":         runtime.HTTPS,
			"tokenSet":      runtime.GithubToken != "",
			"disableCache":  runtime.DisableCache,
			"corsOrigin": func() any {
				if runtime.CorsOrigins.Kind == "any" {
					return "*"
				}
				out := make([]string, 0, len(runtime.CorsOrigins.AllowList))
				for v := range runtime.CorsOrigins.AllowList {
					out = append(out, v)
				}
				return out
			}(),
			"time": time.Now().UTC().Format(time.RFC3339Nano),
		}

		buf, _ := json.MarshalIndent(payload, "", "  ")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(buf)
		return
	}

	region := strings.ToUpper(strings.TrimSpace(r.Header.Get("Cf-Ipcountry")))
	clientIP := getClientIP(r)
	userAgent := r.Header.Get("User-Agent")

	if _, ok := runtime.BlockedRegions[region]; ok && region != "" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("Access denied: service is not available in your region yet."))
		return
	}

	if _, ok := runtime.BlockedIPAddresses[clientIP]; ok && clientIP != "" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("Access denied: your IP address is blocked."))
		return
	}

	if r.Method == http.MethodOptions {
		preflightHeaders := buildPreflightResponseHeaders(r, requestOrigin, runtime)
		for k, vals := range preflightHeaders {
			for _, v := range vals {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	upstreamDomain := runtime.Upstream
	if !isDesktopDevice(userAgent) {
		upstreamDomain = runtime.UpstreamMobile
	}

	upstreamURL := &url.URL{
		Scheme:   "http",
		Host:     upstreamDomain,
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}
	if runtime.HTTPS {
		upstreamURL.Scheme = "https"
	}

	// Apply upstream path prefix.
	if upstreamURL.Path == "" || upstreamURL.Path == "/" {
		upstreamURL.Path = runtime.UpstreamPath
	} else {
		upstreamURL.Path = runtime.UpstreamPath + upstreamURL.Path
	}

	var body io.Reader
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		body = r.Body
	}

	upstreamReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL.String(), body)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("Bad gateway"))
		return
	}

	upstreamReq.Header = buildUpstreamRequestHeaders(r, upstreamDomain, originalHost, originalProto, runtime.GithubToken, runtime.GithubAuthScheme)
	upstreamReq.Host = upstreamDomain
	upstreamReq.ContentLength = r.ContentLength

	resp, err := client.Do(upstreamReq)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("Bad gateway"))
		return
	}
	defer resp.Body.Close()

	upstreamContentType := resp.Header.Get("Content-Type")
	effectiveContentType := upstreamContentType
	normalizedCt := strings.ToLower(strings.TrimSpace(upstreamContentType))
	if normalizedCt == "" || strings.HasPrefix(normalizedCt, "application/octet-stream") {
		if guessed := guessMimeFromPathname(r.URL.Path); guessed != "" {
			effectiveContentType = guessed
		}
	}

	shouldRewrite := shouldRewriteHTML(effectiveContentType)

	cacheControl := computeCacheControl(runtime.DisableCache, effectiveContentType, runtime.CacheControl, runtime.CacheControlMedia, runtime.CacheControlText)

	clientHeaders := buildClientResponseHeaders(resp.Header, upstreamDomain, originalHost, r.URL.Path, cacheControl, requestOrigin, runtime, shouldRewrite)
	for k, vals := range clientHeaders {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}

	w.WriteHeader(resp.StatusCode)

	if r.Method == http.MethodHead {
		return
	}

	if shouldRewrite {
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			return
		}
		rewritten := applyReplacements(string(raw), upstreamDomain, originalHost, runtime.ReplaceDict)
		_, _ = io.Copy(w, bytes.NewBufferString(rewritten))
		return
	}

	_, _ = io.Copy(w, resp.Body)
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func normalizeUpstreamPath(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "/"
	}
	withLeading := trimmed
	if !strings.HasPrefix(withLeading, "/") {
		withLeading = "/" + withLeading
	}
	if strings.HasSuffix(withLeading, "/") {
		return strings.TrimSuffix(withLeading, "/")
	}
	return withLeading
}

func parseCorsOrigins(value string) CorsOrigins {
	raw := strings.TrimSpace(value)
	if raw == "" || raw == "*" {
		return CorsOrigins{Kind: "any"}
	}
	out := make(map[string]struct{})
	for _, part := range strings.Split(raw, ",") {
		s := strings.TrimSpace(part)
		if s == "" {
			continue
		}
		out[s] = struct{}{}
	}
	return CorsOrigins{Kind: "list", AllowList: out}
}

func getOriginalHost(r *http.Request) string {
	xfHost := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if xfHost != "" {
		return xfHost
	}
	if r.Host != "" {
		return r.Host
	}
	return "localhost"
}

func getOriginalProto(r *http.Request) string {
	xfProto := r.Header.Get("X-Forwarded-Proto")
	if xfProto != "" {
		v := strings.TrimSpace(strings.Split(xfProto, ",")[0])
		if v != "" {
			return v
		}
	}
	return "http"
}

func getClientIP(r *http.Request) string {
	if cf := strings.TrimSpace(r.Header.Get("Cf-Connecting-Ip")); cf != "" {
		return cf
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		first := strings.TrimSpace(strings.Split(xff, ",")[0])
		if first != "" {
			return first
		}
	}
	host := strings.TrimSpace(r.RemoteAddr)
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

func isDesktopDevice(userAgent string) bool {
	agents := []string{"Android", "iPhone", "SymbianOS", "Windows Phone", "iPad", "iPod"}
	for _, a := range agents {
		if strings.Contains(userAgent, a) {
			return false
		}
	}
	return true
}

func buildUpstreamRequestHeaders(r *http.Request, upstreamDomain, originalHost, originalProto, githubToken, githubAuthScheme string) http.Header {
	headers := make(http.Header)
	for key, values := range r.Header {
		lowerKey := strings.ToLower(key)
		if shouldSkipUpstreamHeader(lowerKey) {
			continue
		}
		for _, v := range values {
			headers.Add(lowerKey, v)
		}
	}

	headers.Set("referer", originalProto+"://"+originalHost)
	headers.Set("accept-encoding", "identity")

	if strings.TrimSpace(githubToken) != "" {
		scheme := strings.TrimSpace(githubAuthScheme)
		if scheme == "" {
			scheme = "token"
		}
		headers.Set("authorization", scheme+" "+githubToken)
	}

	// Ensure upstream host is correct.
	headers.Set("host", upstreamDomain)
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

func buildClientResponseHeaders(
	upstreamHeaders http.Header,
	upstreamDomain string,
	originalHost string,
	requestPathname string,
	cacheControl string,
	requestOrigin string,
	runtime RuntimeConfig,
	shouldRewrite bool,
) http.Header {
	headers := make(http.Header)

	for key, values := range upstreamHeaders {
		lowerKey := strings.ToLower(key)
		if shouldSkipClientHeader(lowerKey) {
			continue
		}
		if lowerKey == "content-length" && shouldRewrite {
			continue
		}
		for _, v := range values {
			headers.Add(lowerKey, v)
		}
	}

	maybeFixOctetStreamContentType(headers, requestPathname)

	headers.Set("cache-control", cacheControl)

	applyCorsHeaders(headers, requestOrigin, runtime.CorsOrigins, runtime.CorsAllowCredentials, runtime.CorsExposeHeaders)

	if v := headers.Get("x-pjax-url"); v != "" {
		headers.Set("x-pjax-url", strings.ReplaceAll(v, "//"+upstreamDomain, "//"+originalHost))
	}

	if vary := headers.Get("vary"); vary != "" {
		headers.Set("vary", removeVaryHeaderValue(vary, "authorization"))
	}

	return headers
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
		"te",
		"trailer",
		"transfer-encoding",
		"upgrade":
		return true
	default:
		return false
	}
}

func maybeFixOctetStreamContentType(headers http.Header, requestPathname string) {
	ct := strings.ToLower(strings.TrimSpace(headers.Get("content-type")))
	if ct != "" && !strings.HasPrefix(ct, "application/octet-stream") {
		return
	}
	guessed := guessMimeFromPathname(requestPathname)
	if guessed == "" {
		return
	}
	headers.Set("content-type", guessed)
}

func guessMimeFromPathname(pathname string) string {
	base := pathname
	if idx := strings.LastIndex(base, "/"); idx != -1 {
		base = base[idx+1:]
	}
	dot := strings.LastIndex(base, ".")
	if dot == -1 || dot == len(base)-1 {
		return ""
	}
	ext := strings.ToLower(base[dot+1:])

	switch ext {
	case "js", "mjs", "cjs", "jsx":
		return "application/javascript; charset=utf-8"
	case "css":
		return "text/css; charset=utf-8"
	case "html", "htm":
		return "text/html; charset=utf-8"
	case "json", "map":
		return "application/json; charset=utf-8"
	case "yml", "yaml":
		return "application/x-yaml; charset=utf-8"
	case "toml":
		return "application/toml; charset=utf-8"
	case "xml":
		return "application/xml; charset=utf-8"
	case "txt", "md":
		return "text/plain; charset=utf-8"
	case "csv":
		return "text/csv; charset=utf-8"
	case "m3u", "m3u8":
		return "application/vnd.apple.mpegurl; charset=utf-8"
	case "wasm":
		return "application/wasm"
	case "webm":
		return "video/webm"
	case "mp4":
		return "video/mp4"
	case "mp3":
		return "audio/mpeg"
	case "wav":
		return "audio/wav"
	case "ogg":
		return "audio/ogg"
	case "m4a":
		return "audio/mp4"
	case "webp":
		return "image/webp"
	case "avif":
		return "image/avif"
	case "png":
		return "image/png"
	case "ico":
		return "image/x-icon"
	case "cur":
		return "image/x-icon"
	case "jpg", "jpeg":
		return "image/jpeg"
	case "gif":
		return "image/gif"
	case "svg":
		return "image/svg+xml"
	case "woff2":
		return "font/woff2"
	case "woff":
		return "font/woff"
	case "ttf":
		return "font/ttf"
	case "otf":
		return "font/otf"
	case "eot":
		return "application/vnd.ms-fontobject"
	default:
		return ""
	}
}

func shouldRewriteHTML(contentType string) bool {
	ct := strings.ToLower(contentType)
	return strings.Contains(ct, "text/html") && strings.Contains(ct, "utf-8")
}

func computeCacheControl(disableCache bool, contentType, cacheControl, cacheControlMedia, cacheControlText string) string {
	if disableCache {
		return "no-store"
	}
	if strings.TrimSpace(cacheControl) != "" {
		return cacheControl
	}

	ct := strings.ToLower(strings.TrimSpace(contentType))
	if isMediaContentType(ct) {
		return cacheControlMedia
	}
	if isTextContentType(ct) {
		return cacheControlText
	}
	return cacheControlMedia
}

func isMediaContentType(contentType string) bool {
	return strings.HasPrefix(contentType, "image/") ||
		strings.HasPrefix(contentType, "video/") ||
		strings.HasPrefix(contentType, "audio/") ||
		strings.HasPrefix(contentType, "font/")
}

func isTextContentType(contentType string) bool {
	if strings.HasPrefix(contentType, "text/") {
		return true
	}
	switch {
	case strings.Contains(contentType, "application/json"),
		strings.Contains(contentType, "application/javascript"),
		strings.Contains(contentType, "application/x-javascript"),
		strings.Contains(contentType, "application/xml"),
		strings.Contains(contentType, "application/xhtml+xml"),
		strings.Contains(contentType, "application/yaml"),
		strings.Contains(contentType, "application/x-yaml"),
		strings.Contains(contentType, "application/toml"),
		strings.Contains(contentType, "application/vnd.apple.mpegurl"),
		strings.Contains(contentType, "application/x-mpegurl"):
		return true
	default:
		return false
	}
}

func buildPreflightResponseHeaders(r *http.Request, requestOrigin string, runtime RuntimeConfig) http.Header {
	headers := make(http.Header)

	applyCorsHeaders(headers, requestOrigin, runtime.CorsOrigins, runtime.CorsAllowCredentials, runtime.CorsExposeHeaders)
	headers.Set("access-control-allow-methods", "GET,HEAD,OPTIONS")

	requestHeaders := strings.TrimSpace(r.Header.Get("Access-Control-Request-Headers"))
	if requestHeaders == "" {
		requestHeaders = "Range"
	}
	headers.Set("access-control-allow-headers", requestHeaders)
	headers.Set("access-control-max-age", "86400")

	appendVary(headers, "access-control-request-headers")
	headers.Set("cache-control", "no-store")

	return headers
}

func applyCorsHeaders(headers http.Header, requestOrigin string, corsOrigins CorsOrigins, corsAllowCredentials bool, corsExposeHeaders string) {
	originHeader := chooseCorsOrigin(requestOrigin, corsOrigins)
	if originHeader == "" {
		return
	}

	headers.Set("access-control-allow-origin", originHeader)
	if corsAllowCredentials && originHeader != "*" {
		headers.Set("access-control-allow-credentials", "true")
	}
	if strings.TrimSpace(corsExposeHeaders) != "" {
		headers.Set("access-control-expose-headers", corsExposeHeaders)
	}
	if originHeader != "*" {
		appendVary(headers, "origin")
	}
}

func chooseCorsOrigin(requestOrigin string, corsOrigins CorsOrigins) string {
	if corsOrigins.Kind == "" || corsOrigins.Kind == "any" {
		return "*"
	}
	if strings.TrimSpace(requestOrigin) == "" {
		return ""
	}
	if _, ok := corsOrigins.AllowList[requestOrigin]; ok {
		return requestOrigin
	}
	return ""
}

func appendVary(headers http.Header, value string) {
	const key = "vary"
	existing := strings.TrimSpace(headers.Get(key))
	if existing == "" {
		headers.Set(key, value)
		return
	}
	parts := strings.Split(existing, ",")
	for _, p := range parts {
		if strings.EqualFold(strings.TrimSpace(p), value) {
			return
		}
	}
	headers.Set(key, existing+", "+value)
}

func removeVaryHeaderValue(vary, toRemove string) string {
	needle := strings.ToLower(strings.TrimSpace(toRemove))
	parts := strings.Split(vary, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		s := strings.TrimSpace(p)
		if s == "" {
			continue
		}
		if strings.ToLower(s) == needle {
			continue
		}
		out = append(out, s)
	}
	return strings.Join(out, ", ")
}

func applyReplacements(text, upstreamDomain, hostName string, replaceDict map[string]string) string {
	out := text
	keys := make([]string, 0, len(replaceDict))
	for k := range replaceDict {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		rawValue := replaceDict[key]
		resolvedKey := key
		switch key {
		case "$upstream":
			resolvedKey = upstreamDomain
		case "$custom_domain":
			resolvedKey = hostName
		}

		resolvedValue := rawValue
		switch rawValue {
		case "$upstream":
			resolvedValue = upstreamDomain
		case "$custom_domain":
			resolvedValue = hostName
		}

		if strings.TrimSpace(resolvedKey) == "" {
			continue
		}
		out = strings.ReplaceAll(out, resolvedKey, resolvedValue)
	}
	return out
}

func buildBadGateway(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusBadGateway)
	_, _ = w.Write([]byte("Bad gateway"))
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func _unused(_ ...any) {
	// keep lints happy for unused helpers if we expand later
}
