package cdnjsproxy

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"hazuki-go/internal/model"
)

type RuntimeConfig struct {
	Host string
	Port int

	AssetURL string

	GhUserPolicy string // allowlist (default) | denylist
	AllowedUsers map[string]struct{}
	BlockedUsers map[string]struct{}
	DefaultUser  string

	RedisHost string
	RedisPort int

	DefaultTTLSeconds int
	CacheTTLSeconds   map[string]int
}

func BuildRuntimeConfig(cfg model.AppConfig) (RuntimeConfig, error) {
	assetURL := strings.TrimSpace(cfg.Cdnjs.AssetURL)
	if assetURL == "" {
		assetURL = "https://cdn.jsdelivr.net"
	}
	assetURL = strings.TrimRight(assetURL, "/")

	u, err := url.Parse(assetURL)
	if err != nil {
		return RuntimeConfig{}, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return RuntimeConfig{}, errors.New("cdnjs.assetUrl must start with http:// or https://")
	}
	if strings.TrimSpace(u.Host) == "" {
		return RuntimeConfig{}, errors.New("cdnjs.assetUrl host is empty")
	}

	policy := strings.ToLower(strings.TrimSpace(cfg.Cdnjs.GhUserPolicy))
	if policy == "" {
		policy = "allowlist"
	}
	if policy != "allowlist" && policy != "denylist" {
		return RuntimeConfig{}, errors.New("cdnjs.ghUserPolicy must be 'allowlist' or 'denylist'")
	}

	allowed := make(map[string]struct{}, len(cfg.Cdnjs.AllowedGhUsers))
	for _, raw := range cfg.Cdnjs.AllowedGhUsers {
		s := strings.ToLower(strings.TrimSpace(raw))
		if s == "" {
			continue
		}
		allowed[s] = struct{}{}
	}

	blocked := make(map[string]struct{}, len(cfg.Cdnjs.BlockedGhUsers))
	for _, raw := range cfg.Cdnjs.BlockedGhUsers {
		s := strings.ToLower(strings.TrimSpace(raw))
		if s == "" {
			continue
		}
		blocked[s] = struct{}{}
	}

	redisHost := strings.TrimSpace(cfg.Cdnjs.Redis.Host)
	if redisHost == "" {
		redisHost = "redis"
	}
	redisPort := cfg.Cdnjs.Redis.Port
	if redisPort == 0 {
		redisPort = 6379
	}
	if redisPort < 1 || redisPort > 65535 {
		return RuntimeConfig{}, errors.New("cdnjs.redis.port must be 1-65535")
	}

	port := cfg.Ports.Cdnjs
	if port == 0 {
		port = 3001
	}

	defaultTTLSeconds, cacheTTLSeconds := EffectiveCacheTTLConfig(cfg.Cdnjs)

	return RuntimeConfig{
		Host: "0.0.0.0",
		Port: port,

		AssetURL: assetURL,

		GhUserPolicy: policy,
		AllowedUsers: allowed,
		BlockedUsers: blocked,
		DefaultUser:  strings.TrimSpace(cfg.Cdnjs.DefaultGhUser),

		RedisHost: redisHost,
		RedisPort: redisPort,

		DefaultTTLSeconds: defaultTTLSeconds,
		CacheTTLSeconds:   cacheTTLSeconds,
	}, nil
}

func NewDynamicHandler(getRuntime func() RuntimeConfig, getRedis func() *redis.Client) http.Handler {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		runtime := RuntimeConfig{}
		if getRuntime != nil {
			runtime = getRuntime()
		}
		var redisClient *redis.Client
		if getRedis != nil {
			redisClient = getRedis()
		}
		handleRequest(w, r, runtime, redisClient, client)
	})
}

func handleRequest(w http.ResponseWriter, r *http.Request, runtime RuntimeConfig, redisClient *redis.Client, client *http.Client) {
	if (r.Method == http.MethodGet || r.Method == http.MethodHead) && r.URL.Path == "/_hazuki/health" {
		status := "disabled"
		if redisClient != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 250*time.Millisecond)
			defer cancel()
			if err := redisClient.Ping(ctx).Err(); err != nil {
				status = "error"
			} else {
				status = "ok"
			}
		}

		payload := map[string]any{
			"ok":             true,
			"service":        "cdnjs",
			"host":           runtime.Host,
			"port":           runtime.Port,
			"assetUrl":       runtime.AssetURL,
			"ghUserPolicy":   runtime.GhUserPolicy,
			"defaultUserSet": strings.TrimSpace(runtime.DefaultUser) != "",
			"allowedUsersCount": func() int {
				if runtime.AllowedUsers == nil {
					return 0
				}
				return len(runtime.AllowedUsers)
			}(),
			"blockedUsersCount": func() int {
				if runtime.BlockedUsers == nil {
					return 0
				}
				return len(runtime.BlockedUsers)
			}(),
			"redis": map[string]any{
				"host":   runtime.RedisHost,
				"port":   runtime.RedisPort,
				"status": status,
			},
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

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := r.URL.Path
	if strings.HasPrefix(path, "/gh/") {
		user, filePath, ok := parseGhPath(path)
		if !ok {
			http.NotFound(w, r)
			return
		}
		if ok, msg := canAccessGhUser(user, runtime); !ok {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			if r.Method == http.MethodHead {
				return
			}
			_, _ = w.Write([]byte(msg))
			return
		}

		cdnURL := runtime.AssetURL + "/gh/" + user + "/" + filePath
		fetchWithCache(w, r, runtime, redisClient, client, cdnURL, path)
		return
	}

	reqPath := strings.TrimPrefix(path, "/")
	if reqPath == "works" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write([]byte("it works"))
		return
	}

	if strings.TrimSpace(runtime.DefaultUser) == "" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write([]byte("DEFAULT_GH_USER is empty"))
		return
	}

	cdnURL := runtime.AssetURL + "/gh/" + runtime.DefaultUser + "/" + reqPath
	fetchWithCache(w, r, runtime, redisClient, client, cdnURL, path)
}

func parseGhPath(path string) (user, filePath string, ok bool) {
	rest := strings.TrimPrefix(path, "/gh/")
	if rest == "" {
		return "", "", false
	}
	idx := strings.Index(rest, "/")
	if idx <= 0 || idx == len(rest)-1 {
		return "", "", false
	}
	return rest[:idx], rest[idx+1:], true
}

func canAccessGhUser(user string, runtime RuntimeConfig) (ok bool, message string) {
	userKey := strings.ToLower(strings.TrimSpace(user))
	policy := strings.ToLower(strings.TrimSpace(runtime.GhUserPolicy))
	if policy == "" {
		policy = "allowlist"
	}

	switch policy {
	case "denylist":
		if _, blocked := runtime.BlockedUsers[userKey]; blocked {
			return false, `Access denied: User "` + user + `" is blocked`
		}
		return true, ""
	default: // allowlist
		if _, allowed := runtime.AllowedUsers[userKey]; allowed {
			return true, ""
		}
		return false, `Access denied: User "` + user + `" is not authorized`
	}
}

const builtInDefaultTTLSeconds = 86400

var builtInCacheTTLSeconds = map[string]int{
	// Node defaults (kept for compatibility).
	"js":    2592000,
	"css":   2592000,
	"png":   2592000,
	"jpg":   2592000,
	"jpeg":  2592000,
	"gif":   2592000,
	"svg":   2592000,
	"ico":   2592000,
	"woff":  2592000,
	"woff2": 2592000,
	"ttf":   2592000,
	"eot":   2592000,
	"webp":  2592000,
	"moc3":  2592000,
	"map":   2592000,
	"cur":   2592000,
	"mp4":   604800,
	"mp3":   604800,
	"pdf":   604800,
	"json":  86400,
	"xml":   86400,
	"txt":   86400,
	"html":  3600,

	// Extra common extensions (Go version is intentionally more complete).
	"mjs":   2592000,
	"cjs":   2592000,
	"wasm":  2592000,
	"avif":  2592000,
	"apng":  2592000,
	"bmp":   2592000,
	"tif":   2592000,
	"tiff":  2592000,
	"otf":   2592000,
	"svgz":  2592000,
	"webm":  604800,
	"m4a":   604800,
	"aac":   604800,
	"ogg":   604800,
	"wav":   604800,
	"flac":  604800,
	"htm":   3600,
	"md":    86400,
	"yml":   86400,
	"yaml":  86400,
	"toml":  86400,
	"jsonc": 86400,
}

func EffectiveCacheTTLConfig(cfg model.CdnjsConfig) (defaultTTLSeconds int, cacheTTLSeconds map[string]int) {
	defaultTTLSeconds = builtInDefaultTTLSeconds
	if cfg.DefaultTTLSeconds > 0 {
		defaultTTLSeconds = cfg.DefaultTTLSeconds
	}

	cacheTTLSeconds = make(map[string]int, len(builtInCacheTTLSeconds)+len(cfg.CacheTTLSeconds))
	for ext, ttl := range builtInCacheTTLSeconds {
		cacheTTLSeconds[ext] = ttl
	}
	for rawExt, ttl := range cfg.CacheTTLSeconds {
		ext := normalizeExt(rawExt)
		if ext == "" || ttl <= 0 {
			continue
		}
		cacheTTLSeconds[ext] = ttl
	}
	return defaultTTLSeconds, cacheTTLSeconds
}

func normalizeExt(ext string) string {
	s := strings.ToLower(strings.TrimSpace(ext))
	s = strings.TrimPrefix(s, ".")
	return s
}

func getCacheTTLSeconds(requestPath string, cacheTTLSeconds map[string]int, defaultTTLSeconds int) int {
	if defaultTTLSeconds <= 0 {
		defaultTTLSeconds = builtInDefaultTTLSeconds
	}

	ext := extractExtension(requestPath)
	if ext == "" {
		return defaultTTLSeconds
	}
	if cacheTTLSeconds != nil {
		if ttl, ok := cacheTTLSeconds[ext]; ok && ttl > 0 {
			return ttl
		}
	}
	return defaultTTLSeconds
}

func extractExtension(requestPath string) string {
	base := requestPath
	if idx := strings.LastIndex(base, "/"); idx != -1 {
		base = base[idx+1:]
	}
	base = strings.TrimSpace(base)
	if base == "" {
		return ""
	}
	dot := strings.LastIndex(base, ".")
	if dot <= 0 || dot == len(base)-1 {
		return ""
	}
	return strings.ToLower(base[dot+1:])
}

func fetchWithCache(w http.ResponseWriter, r *http.Request, runtime RuntimeConfig, redisClient *redis.Client, client *http.Client, cdnURL, reqPath string) {
	ttlSeconds := getCacheTTLSeconds(reqPath, runtime.CacheTTLSeconds, runtime.DefaultTTLSeconds)

	var cached []byte
	var cachedType string
	if redisClient != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 250*time.Millisecond)
		cached, _ = redisClient.Get(ctx, cdnURL).Bytes()
		cachedType, _ = redisClient.Get(ctx, cdnURL+":type").Result()
		cancel()
	}

	if cached != nil && strings.TrimSpace(cachedType) != "" {
		writeBody(w, r, cached, cachedType, ttlSeconds, "HIT")
		return
	}

	upReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, cdnURL, nil)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write([]byte("Fetch error: " + err.Error()))
		return
	}

	resp, err := client.Do(upReq)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write([]byte("Fetch error: " + err.Error()))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		w.Header().Set("X-Proxy-Cache", "BYPASS")
		w.Header().Set("Cache-Control", "no-store")
		if ct := strings.TrimSpace(resp.Header.Get("Content-Type")); ct != "" {
			w.Header().Set("Content-Type", ct)
		} else {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		}
		w.WriteHeader(resp.StatusCode)
		if r.Method == http.MethodHead {
			return
		}
		_, _ = io.Copy(w, resp.Body)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write([]byte("Fetch error: " + err.Error()))
		return
	}

	contentType := strings.TrimSpace(resp.Header.Get("Content-Type"))
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	if redisClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 750*time.Millisecond)
		ttl := time.Duration(ttlSeconds) * time.Second
		pipe := redisClient.Pipeline()
		pipe.SetEx(ctx, cdnURL, body, ttl)
		pipe.SetEx(ctx, cdnURL+":type", contentType, ttl)
		_, _ = pipe.Exec(ctx)
		cancel()
	}

	writeBody(w, r, body, contentType, ttlSeconds, "MISS")
}

func writeBody(w http.ResponseWriter, r *http.Request, body []byte, contentType string, ttlSeconds int, cacheStatus string) {
	w.Header().Set("X-Proxy-Cache", cacheStatus)
	w.Header().Set("Cache-Control", "public, max-age="+strconvItoa(ttlSeconds))
	w.Header().Set("Content-Type", contentType)

	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}

	if shouldGzip(r, contentType, body) {
		w.Header().Set("Content-Encoding", "gzip")
		appendVary(w.Header(), "Accept-Encoding")
		w.WriteHeader(http.StatusOK)
		gz := gzip.NewWriter(w)
		_, _ = gz.Write(body)
		_ = gz.Close()
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func shouldGzip(r *http.Request, contentType string, body []byte) bool {
	if len(body) < 1024 {
		return false
	}
	ae := r.Header.Get("Accept-Encoding")
	if !strings.Contains(ae, "gzip") {
		return false
	}
	return isCompressibleContentType(contentType)
}

func isCompressibleContentType(contentType string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if strings.HasPrefix(ct, "text/") {
		return true
	}
	switch {
	case strings.Contains(ct, "application/javascript"),
		strings.Contains(ct, "application/x-javascript"),
		strings.Contains(ct, "application/json"),
		strings.Contains(ct, "application/xml"),
		strings.Contains(ct, "application/xhtml+xml"),
		strings.Contains(ct, "application/x-yaml"),
		strings.Contains(ct, "application/toml"),
		strings.Contains(ct, "application/vnd.apple.mpegurl"):
		return true
	default:
		return false
	}
}

func appendVary(headers http.Header, value string) {
	const key = "Vary"
	existing := strings.TrimSpace(headers.Get(key))
	if existing == "" {
		headers.Set(key, value)
		return
	}
	for _, p := range strings.Split(existing, ",") {
		if strings.EqualFold(strings.TrimSpace(p), value) {
			return
		}
	}
	headers.Set(key, existing+", "+value)
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
