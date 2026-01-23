package torcherinoproxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"hazuki-go/internal/model"
	"hazuki-go/internal/proxy/upstreamhttp"
)

type RuntimeConfig struct {
	Host string
	Port int

	DefaultTarget string
	HostMapping   map[string]string

	WorkerSecretKey       string
	WorkerSecretHeaders   []string
	WorkerSecretHeaderMap map[string]string
}

func BuildRuntimeConfig(cfg model.AppConfig) (RuntimeConfig, error) {
	port := cfg.Ports.Torcherino
	if port == 0 {
		port = 3000
	}

	hostMapping := normalizeHostMapping(cfg.Torcherino.HostMapping)
	secretHeaders := normalizeHeaderNames(cfg.Torcherino.WorkerSecretHeaders)
	secretHeaderMap := normalizeHeaderMap(cfg.Torcherino.WorkerSecretHeaderMap)

	return RuntimeConfig{
		Host: "0.0.0.0",
		Port: port,

		DefaultTarget: strings.TrimSpace(cfg.Torcherino.DefaultTarget),
		HostMapping:   hostMapping,

		WorkerSecretKey:       cfg.Torcherino.WorkerSecretKey,
		WorkerSecretHeaders:   secretHeaders,
		WorkerSecretHeaderMap: secretHeaderMap,
	}, nil
}

func NewHandler(runtime RuntimeConfig) http.Handler {
	return NewDynamicHandler(func() RuntimeConfig { return runtime })
}

func NewDynamicHandler(getRuntime func() RuntimeConfig) http.Handler {
	client := upstreamhttp.NewClient(upstreamhttp.Options{
		FollowRedirects: false,
		Timeout:         60 * time.Second,
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		runtime := RuntimeConfig{}
		if getRuntime != nil {
			runtime = getRuntime()
		}
		handleRequest(w, r, runtime, client)
	})
}

var (
	pagesDevRe = regexp.MustCompile(`(?i)https?://[^/"'\s]*\.pages\.dev`)
	hfSpaceRe  = regexp.MustCompile(`(?i)https?://[^/"'\s]*\.hf\.space`)
)

func handleRequest(w http.ResponseWriter, r *http.Request, runtime RuntimeConfig, client *http.Client) {
	if (r.Method == http.MethodGet || r.Method == http.MethodHead) && r.URL.Path == "/_hazuki/health" {
		if !isLoopbackRemoteAddr(r.RemoteAddr) {
			http.NotFound(w, r)
			return
		}

		keys := make([]string, 0, len(runtime.WorkerSecretHeaderMap))
		for k := range runtime.WorkerSecretHeaderMap {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		payload := map[string]any{
			"ok":                        true,
			"service":                   "torcherino",
			"host":                      runtime.Host,
			"port":                      runtime.Port,
			"defaultTargetSet":          strings.TrimSpace(runtime.DefaultTarget) != "",
			"hostMappingCount":          len(runtime.HostMapping),
			"workerSecretSet":           strings.TrimSpace(runtime.WorkerSecretKey) != "",
			"workerSecretHeaders":       runtime.WorkerSecretHeaders,
			"workerSecretHeaderMapKeys": keys,
			"time":                      time.Now().UTC().Format(time.RFC3339Nano),
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

	reqHost := normalizeHostOnly(r.Host)
	targetHost := ""
	if reqHost != "" {
		targetHost = runtime.HostMapping[strings.ToLower(reqHost)]
	}
	if strings.TrimSpace(targetHost) == "" {
		targetHost = strings.TrimSpace(runtime.DefaultTarget)
	}
	if strings.TrimSpace(targetHost) == "" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("Bad Gateway: DEFAULT_TARGET is empty"))
		return
	}

	upstreamURL := &url.URL{
		Scheme:   "https",
		Host:     targetHost,
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}

	reqOrigin := buildRequestOrigin(r)

	var body io.Reader
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		body = r.Body
	}

	upReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL.String(), body)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("Bad Gateway"))
		return
	}
	upReq.Host = targetHost
	upReq.ContentLength = r.ContentLength
	upReq.Header = cloneRequestHeaders(r.Header)
	upReq.Header.Set("Host", targetHost)
	upReq.Header.Set("Accept-Encoding", "identity")

	if strings.TrimSpace(runtime.WorkerSecretKey) != "" {
		headerNames := runtime.WorkerSecretHeaders
		if len(headerNames) == 0 {
			headerNames = []string{"x-forwarded-by-worker"}
		}
		for _, headerName := range headerNames {
			if headerName == "" {
				continue
			}
			upReq.Header.Set(headerName, runtime.WorkerSecretKey)
		}
	}
	for headerName, headerValue := range runtime.WorkerSecretHeaderMap {
		if headerName == "" || headerValue == "" {
			continue
		}
		upReq.Header.Set(headerName, headerValue)
	}

	resp, err := client.Do(upReq)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("Bad Gateway"))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		copyResponseHeaders(w.Header(), resp.Header, true)
		if loc := resp.Header.Get("Location"); strings.TrimSpace(loc) != "" {
			w.Header().Set("Location", rewriteBody(loc, reqOrigin))
		}
		w.WriteHeader(resp.StatusCode)
		return
	}

	contentType := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Type")))
	shouldRewrite := strings.Contains(contentType, "application/json") || strings.Contains(contentType, "text/html")
	if shouldRewrite {
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("Bad Gateway"))
			return
		}
		rewritten := rewriteBody(string(raw), reqOrigin)

		copyResponseHeaders(w.Header(), resp.Header, false)
		w.Header().Del("Content-Length")
		w.Header().Del("Transfer-Encoding")
		w.Header().Set("Content-Length", strconvItoa(len([]byte(rewritten))))

		w.WriteHeader(resp.StatusCode)
		if r.Method == http.MethodHead {
			return
		}
		_, _ = io.Copy(w, bytes.NewBufferString(rewritten))
		return
	}

	copyResponseHeaders(w.Header(), resp.Header, true)
	w.WriteHeader(resp.StatusCode)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = io.Copy(w, resp.Body)
}

func rewriteBody(body, reqOrigin string) string {
	if strings.TrimSpace(reqOrigin) == "" {
		return body
	}
	out := pagesDevRe.ReplaceAllString(body, reqOrigin)
	out = hfSpaceRe.ReplaceAllString(out, reqOrigin)
	return out
}

func buildRequestOrigin(r *http.Request) string {
	proto := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]))
	if proto == "" {
		proto = "http"
	}
	host := strings.TrimSpace(r.Host)
	if host == "" {
		host = "localhost"
	}
	return proto + "://" + host
}

func normalizeHostOnly(hostport string) string {
	hp := strings.TrimSpace(hostport)
	if hp == "" {
		return ""
	}
	if strings.HasPrefix(hp, "[") && strings.Contains(hp, "]") {
		if h, _, err := net.SplitHostPort(hp); err == nil {
			return strings.Trim(h, "[]")
		}
		return strings.Trim(hp, "[]")
	}
	if h, _, err := net.SplitHostPort(hp); err == nil {
		return h
	}
	if strings.Count(hp, ":") > 1 {
		return strings.Trim(hp, "[]")
	}
	return strings.Split(hp, ":")[0]
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

func cloneRequestHeaders(src http.Header) http.Header {
	out := make(http.Header)
	for k, vals := range src {
		lk := strings.ToLower(k)
		if isHopByHopHeader(lk) {
			continue
		}
		for _, v := range vals {
			out.Add(k, v)
		}
	}
	return out
}

func copyResponseHeaders(dst http.Header, src http.Header, allowContentEncoding bool) {
	for k, vals := range src {
		lk := strings.ToLower(k)
		if isHopByHopHeader(lk) {
			continue
		}
		if !allowContentEncoding && lk == "content-encoding" {
			continue
		}
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
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

func normalizeHostMapping(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		host := strings.ToLower(strings.TrimSpace(k))
		target := strings.TrimSpace(v)
		if host == "" || target == "" {
			continue
		}
		out[host] = target
	}
	return out
}

func normalizeHeaderName(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

var headerNameRe = regexp.MustCompile(`^[!#$%&'*+.^_` + "`" + `|~0-9a-z-]+$`)

func isValidHeaderName(name string) bool {
	return headerNameRe.MatchString(name)
}

func normalizeHeaderNames(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		name := normalizeHeaderName(raw)
		if name == "" || !isValidHeaderName(name) {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out
}

func normalizeHeaderMap(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		name := normalizeHeaderName(k)
		if name == "" || !isValidHeaderName(name) {
			continue
		}
		value := strings.TrimSpace(v)
		if value == "" {
			continue
		}
		out[name] = value
	}
	return out
}

func strconvItoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [32]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + (n % 10))
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
