package sakuyaodproxy

import (
	"crypto/tls"
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
	"hazuki-go/internal/proxy/upstreamhttp"
)

type RuntimeConfig struct {
	Host string
	Port int

	Upstream       string
	UpstreamMobile string
	UpstreamPath   string
	HTTPS          bool

	DisableCache bool

	BlockedRegions     map[string]struct{}
	BlockedIPAddresses map[string]struct{}

	ReplaceDict map[string]string
}

func BuildRuntimeConfig(cfg model.AppConfig) (RuntimeConfig, error) {
	port := cfg.Ports.SakuyaOneDrive
	if port == 0 {
		port = 3201
	}

	upstream := strings.TrimSpace(cfg.Sakuya.OneDrive.Upstream)
	if upstream != "" {
		if strings.Contains(upstream, "://") {
			return RuntimeConfig{}, errors.New("sakuya.onedrive.upstream must be a host (no scheme)")
		}
		if strings.Contains(upstream, "/") {
			return RuntimeConfig{}, errors.New("sakuya.onedrive.upstream must not contain '/'")
		}
	}

	upstreamMobile := strings.TrimSpace(cfg.Sakuya.OneDrive.UpstreamMobile)
	if upstreamMobile == "" {
		upstreamMobile = upstream
	}
	if upstreamMobile != "" {
		if strings.Contains(upstreamMobile, "://") {
			return RuntimeConfig{}, errors.New("sakuya.onedrive.upstreamMobile must be a host (no scheme)")
		}
		if strings.Contains(upstreamMobile, "/") {
			return RuntimeConfig{}, errors.New("sakuya.onedrive.upstreamMobile must not contain '/'")
		}
	}

	upstreamPath := normalizeUpstreamPath(cfg.Sakuya.OneDrive.UpstreamPath)
	if strings.TrimSpace(cfg.Sakuya.OneDrive.UpstreamPath) == "" {
		upstreamPath = normalizeUpstreamPath("/")
	}

	regions := cfg.Sakuya.OneDrive.BlockedRegions
	if regions == nil {
		regions = []string{"KP", "SY", "PK", "CU"}
	}
	ips := cfg.Sakuya.OneDrive.BlockedIpAddresses
	if ips == nil {
		ips = []string{"0.0.0.0", "127.0.0.1"}
	}

	blockedRegions := make(map[string]struct{}, len(regions))
	for _, r := range regions {
		rr := strings.ToUpper(strings.TrimSpace(r))
		if rr == "" {
			continue
		}
		blockedRegions[rr] = struct{}{}
	}
	blockedIPs := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		s := strings.TrimSpace(ip)
		if s == "" {
			continue
		}
		blockedIPs[s] = struct{}{}
	}

	replaceDict := cfg.Sakuya.OneDrive.ReplaceDict
	if replaceDict == nil {
		replaceDict = map[string]string{
			"$upstream":    "$custom_domain",
			"//sunpma.com": "",
		}
	}

	return RuntimeConfig{
		Host: "0.0.0.0",
		Port: port,

		Upstream:       upstream,
		UpstreamMobile: upstreamMobile,
		UpstreamPath:   upstreamPath,
		HTTPS:          cfg.Sakuya.OneDrive.HTTPS,

		DisableCache: cfg.Sakuya.OneDrive.DisableCache,

		BlockedRegions:     blockedRegions,
		BlockedIPAddresses: blockedIPs,

		ReplaceDict: replaceDict,
	}, nil
}

type Handler struct {
	getRuntime func() RuntimeConfig

	client *http.Client
}

type HandlerOptions struct {
	GetRuntime func() RuntimeConfig

	// Optional. If nil, sensible defaults are used.
	Client *http.Client
}

func NewHandler(opts HandlerOptions) *Handler {
	getRuntime := opts.GetRuntime
	if getRuntime == nil {
		getRuntime = func() RuntimeConfig { return RuntimeConfig{} }
	}
	client := opts.Client
	if client == nil {
		client = upstreamhttp.NewClient(upstreamhttp.Options{
			Timeout:         0, // allow large downloads
			FollowRedirects: true,
		})
	}

	return &Handler{
		getRuntime: getRuntime,
		client:     client,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	runtime := RuntimeConfig{}
	if h.getRuntime != nil {
		runtime = h.getRuntime()
	}
	handleRequest(w, r, runtime, h.client)
}

func handleRequest(w http.ResponseWriter, r *http.Request, runtime RuntimeConfig, client *http.Client) {
	if r == nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Health (loopback only).
	if (r.Method == http.MethodGet || r.Method == http.MethodHead) && r.URL.Path == "/_hazuki/health" {
		if !isLoopbackRemoteAddr(r.RemoteAddr) {
			http.NotFound(w, r)
			return
		}
		writeHealth(w, r, runtime)
		return
	}

	// Handle CORS preflight.
	if r.Method == http.MethodOptions {
		writeCORSPreflight(w, r)
		return
	}

	// Basic config sanity.
	upstreamConfigured := strings.TrimSpace(runtime.Upstream) != "" || strings.TrimSpace(runtime.UpstreamMobile) != ""
	if !upstreamConfigured {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("Bad gateway"))
		return
	}

	// Path rules (same as od.txt).
	if r.URL.Path == "/personal" || !strings.Contains(r.URL.Path, "/personal/") {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.WriteHeader(http.StatusNotFound)
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write([]byte("404"))
		return
	}

	region := strings.ToUpper(strings.TrimSpace(r.Header.Get("cf-ipcountry")))
	clientIP := getClientIP(r)
	userAgent := r.Header.Get("user-agent")

	if _, ok := runtime.BlockedRegions[region]; ok && region != "" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("Access denied: WorkersProxy is not available in your region yet."))
		return
	}
	if _, ok := runtime.BlockedIPAddresses[clientIP]; ok && clientIP != "" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("Access denied: Your IP address is blocked by WorkersProxy."))
		return
	}

	originalHost := getOriginalHost(r)
	originalProto := getOriginalProto(r)

	upstreamDomain := runtime.Upstream
	if !isDesktopDevice(userAgent) {
		if strings.TrimSpace(runtime.UpstreamMobile) != "" {
			upstreamDomain = runtime.UpstreamMobile
		}
	}
	if strings.TrimSpace(upstreamDomain) == "" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("Bad gateway"))
		return
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

	// WebSocket upgrade: tunnel (no body).
	if isWebSocketUpgrade(r) {
		tunnelWebSocket(w, r, upstreamURL, upstreamDomain, originalProto, originalHost)
		return
	}

	var body io.Reader
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		body = r.Body
	}

	upstreamReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL.String(), body)
	if err != nil {
		buildBadGateway(w, r.Method)
		return
	}
	upstreamReq.Header = buildUpstreamRequestHeaders(r, upstreamDomain, originalHost, originalProto)
	upstreamReq.Host = upstreamDomain
	upstreamReq.ContentLength = r.ContentLength

	resp, err := client.Do(upstreamReq)
	if err != nil {
		buildBadGateway(w, r.Method)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	shouldRewrite := shouldRewriteHTML(resp.Header.Get("content-type"))

	clientHeaders := buildClientResponseHeaders(resp.Header, upstreamDomain, originalHost, runtime.DisableCache, shouldRewrite)
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
		_, _ = io.Copy(w, strings.NewReader(rewritten))
		return
	}

	_, _ = io.Copy(w, resp.Body)
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
	if r.TLS != nil {
		return "https"
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

func writeHealth(w http.ResponseWriter, r *http.Request, runtime RuntimeConfig) {
	payload := map[string]any{
		"ok":      true,
		"service": "sakuya-onedrive",
		"host":    runtime.Host,
		"port":    runtime.Port,
		"onedrive": map[string]any{
			"upstream":       runtime.Upstream,
			"upstreamMobile": runtime.UpstreamMobile,
			"upstreamPath":   runtime.UpstreamPath,
			"https":          runtime.HTTPS,
			"disableCache":   runtime.DisableCache,
		},
		"time": time.Now().UTC().Format(time.RFC3339Nano),
	}
	buf, _ := json.MarshalIndent(payload, "", "  ")
	w.Header().Set("content-type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(buf)
}

func buildBadGateway(w http.ResponseWriter, method string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusBadGateway)
	if method == http.MethodHead {
		return
	}
	_, _ = w.Write([]byte("Bad gateway"))
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

func shouldRewriteHTML(contentType string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if ct == "" {
		return false
	}
	if !strings.Contains(ct, "text/html") {
		return false
	}
	return strings.Contains(ct, "utf-8")
}

func buildUpstreamRequestHeaders(r *http.Request, upstreamDomain, originalHost, originalProto string) http.Header {
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

func buildClientResponseHeaders(upstreamHeaders http.Header, upstreamDomain string, originalHost string, disableCache bool, shouldRewrite bool) http.Header {
	headers := make(http.Header)
	for key, values := range upstreamHeaders {
		lowerKey := strings.ToLower(key)
		if isHopByHopHeader(lowerKey) {
			continue
		}
		if lowerKey == "content-length" && shouldRewrite {
			continue
		}
		for _, v := range values {
			headers.Add(lowerKey, v)
		}
	}

	if disableCache {
		headers.Set("cache-control", "no-store")
	}

	headers.Set("access-control-allow-origin", "*")
	headers.Set("access-control-allow-credentials", "true")
	headers.Del("content-security-policy")
	headers.Del("content-security-policy-report-only")
	headers.Del("clear-site-data")

	if v := headers.Get("x-pjax-url"); v != "" {
		headers.Set("x-pjax-url", strings.ReplaceAll(v, "//"+upstreamDomain, "//"+originalHost))
	}

	return headers
}

func applyReplacements(text, upstreamDomain, hostName string, replaceDict map[string]string) string {
	out := text
	if replaceDict == nil {
		return out
	}
	keys := make([]string, 0, len(replaceDict))
	for k := range replaceDict {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		rawValue := replaceDict[key]
		resolvedKey := key
		switch key {
		case "$upstream", "$$upstream":
			resolvedKey = upstreamDomain
		case "$custom_domain", "$$custom_domain":
			resolvedKey = hostName
		}

		resolvedValue := rawValue
		switch rawValue {
		case "$upstream", "$$upstream":
			resolvedValue = upstreamDomain
		case "$custom_domain", "$$custom_domain":
			resolvedValue = hostName
		}

		if strings.TrimSpace(resolvedKey) == "" {
			continue
		}
		out = strings.ReplaceAll(out, resolvedKey, resolvedValue)
	}
	return out
}

func writeCORSPreflight(w http.ResponseWriter, r *http.Request) {
	corsHeaders := map[string]string{
		"access-control-allow-origin":      "*",
		"access-control-allow-methods":     "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS",
		"access-control-allow-credentials": "true",
		"access-control-max-age":           "86400",
	}
	if r != nil && r.Header.Get("Origin") != "" && r.Header.Get("Access-Control-Request-Method") != "" {
		for k, v := range corsHeaders {
			w.Header().Set(k, v)
		}
		w.Header().Set("access-control-allow-headers", r.Header.Get("Access-Control-Request-Headers"))
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("allow", "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS")
	w.WriteHeader(http.StatusNoContent)
}

func isHopByHopHeader(lowerKey string) bool {
	switch lowerKey {
	case "connection",
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

func isLoopbackRemoteAddr(remoteAddr string) bool {
	host := strings.TrimSpace(remoteAddr)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isWebSocketUpgrade(r *http.Request) bool {
	if r == nil {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket") {
		return false
	}
	conn := strings.ToLower(r.Header.Get("Connection"))
	return strings.Contains(conn, "upgrade")
}

func tunnelWebSocket(w http.ResponseWriter, r *http.Request, upstreamURL *url.URL, upstreamHost string, originalProto string, originalHost string) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Not supported", http.StatusNotImplemented)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	defer func() { _ = clientConn.Close() }()

	upAddr := upstreamHost
	if _, _, err := net.SplitHostPort(upstreamHost); err != nil {
		if upstreamURL != nil && strings.EqualFold(upstreamURL.Scheme, "https") {
			upAddr = net.JoinHostPort(upstreamHost, "443")
		} else {
			upAddr = net.JoinHostPort(upstreamHost, "80")
		}
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	var upstreamConn net.Conn
	if upstreamURL != nil && strings.EqualFold(upstreamURL.Scheme, "https") {
		tlsCfg := &tls.Config{ServerName: strings.TrimSpace(strings.Split(upstreamHost, ":")[0])}
		upstreamConn, err = tls.DialWithDialer(dialer, "tcp", upAddr, tlsCfg)
	} else {
		upstreamConn, err = dialer.Dial("tcp", upAddr)
	}
	if err != nil {
		return
	}
	defer func() { _ = upstreamConn.Close() }()

	req := r.Clone(r.Context())
	req.URL = &url.URL{Path: upstreamURL.Path, RawQuery: upstreamURL.RawQuery}
	req.Host = upstreamHost
	req.RequestURI = ""
	req.Header = buildUpstreamRequestHeaders(r, upstreamHost, originalHost, originalProto)
	req.Header.Set("connection", "Upgrade")
	req.Header.Set("upgrade", "websocket")

	_ = req.Write(upstreamConn)

	errCh := make(chan error, 2)
	go func() {
		_, e := io.Copy(upstreamConn, clientConn)
		errCh <- e
	}()
	go func() {
		_, e := io.Copy(clientConn, upstreamConn)
		errCh <- e
	}()

	<-errCh
}

func _unused(_ ...any) {
	// keep lints happy if we expand later
}
