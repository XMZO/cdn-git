package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"hazuki-go/internal/storage"
)

func isSecureRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	xfProto := r.Header.Get("X-Forwarded-Proto")
	proto := strings.ToLower(strings.TrimSpace(strings.Split(xfProto, ",")[0]))
	return proto == "https"
}

func requestScheme(r *http.Request) string {
	if isSecureRequest(r) || r.TLS != nil {
		return "https"
	}
	return "http"
}

func requestHostName(r *http.Request) string {
	host := strings.TrimSpace(r.Host)
	if host == "" {
		return "127.0.0.1"
	}
	hostName := host
	if h, _, err := net.SplitHostPort(host); err == nil && strings.TrimSpace(h) != "" {
		hostName = h
	}
	hostName = strings.TrimPrefix(hostName, "[")
	hostName = strings.TrimSuffix(hostName, "]")
	if hostName == "" {
		return "127.0.0.1"
	}
	return hostName
}

func baseURLForPort(r *http.Request, port int) string {
	scheme := requestScheme(r)
	hostPort := net.JoinHostPort(requestHostName(r), strconv.Itoa(port))
	return scheme + "://" + hostPort
}

func checkRedisStatus(ctx context.Context, host string, port int) redisStatus {
	host = strings.TrimSpace(host)
	if host == "" || port <= 0 || port > 65535 {
		return redisStatus{Status: "disabled"}
	}

	addr := ""
	if h, p, err := net.SplitHostPort(host); err == nil && strings.TrimSpace(h) != "" && strings.TrimSpace(p) != "" {
		addr = net.JoinHostPort(h, p)
	} else {
		addr = net.JoinHostPort(host, strconv.Itoa(port))
	}

	client := redis.NewClient(&redis.Options{
		Addr:         addr,
		MaxRetries:   0,
		PoolSize:     1,
		DialTimeout:  200 * time.Millisecond,
		ReadTimeout:  200 * time.Millisecond,
		WriteTimeout: 200 * time.Millisecond,
	})
	defer func() { _ = client.Close() }()

	pingCtx, cancel := context.WithTimeout(ctx, 350*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := client.Ping(pingCtx).Err()
	latency := time.Since(start)

	if err != nil {
		return redisStatus{
			Addr:      addr,
			Status:    "error",
			LatencyMS: latency.Milliseconds(),
			Error:     err.Error(),
		}
	}

	st := redisStatus{
		Addr:      addr,
		Status:    "ok",
		LatencyMS: latency.Milliseconds(),
	}

	infoCtx, cancel := context.WithTimeout(ctx, 450*time.Millisecond)
	defer cancel()
	infoStr, err := client.Info(infoCtx, "server", "clients", "memory", "stats").Result()
	if err == nil && strings.TrimSpace(infoStr) != "" {
		for _, line := range strings.Split(infoStr, "\n") {
			l := strings.TrimSpace(line)
			if l == "" || strings.HasPrefix(l, "#") {
				continue
			}
			key, val, ok := strings.Cut(l, ":")
			if !ok {
				continue
			}
			key = strings.TrimSpace(key)
			val = strings.TrimSpace(val)
			switch key {
			case "redis_version":
				st.ServerVersion = val
			case "uptime_in_seconds":
				if n, err := strconv.ParseInt(val, 10, 64); err == nil {
					st.UptimeSeconds = n
				}
			case "connected_clients":
				if n, err := strconv.ParseInt(val, 10, 64); err == nil {
					st.ConnectedClients = n
				}
			case "used_memory_human":
				st.UsedMemoryHuman = val
			case "keyspace_hits":
				if n, err := strconv.ParseInt(val, 10, 64); err == nil {
					st.KeyspaceHits = n
				}
			case "keyspace_misses":
				if n, err := strconv.ParseInt(val, 10, 64); err == nil {
					st.KeyspaceMisses = n
				}
			}
		}
	}

	dbSizeCtx, cancel := context.WithTimeout(ctx, 450*time.Millisecond)
	defer cancel()
	if n, err := client.DBSize(dbSizeCtx).Result(); err == nil {
		st.DBSize = n
	}

	return st
}

func newRedisAdminClient(host string, port int) (*redis.Client, string, bool) {
	host = strings.TrimSpace(host)
	if host == "" || port <= 0 || port > 65535 {
		return nil, "", false
	}

	addr := ""
	if h, p, err := net.SplitHostPort(host); err == nil && strings.TrimSpace(h) != "" && strings.TrimSpace(p) != "" {
		addr = net.JoinHostPort(h, p)
	} else {
		addr = net.JoinHostPort(host, strconv.Itoa(port))
	}

	return redis.NewClient(&redis.Options{
		Addr:         addr,
		MaxRetries:   1,
		PoolSize:     2,
		DialTimeout:  500 * time.Millisecond,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	}), addr, true
}

func disabledServiceStatus(port int) serviceStatus {
	if port <= 0 || port > 65535 {
		return serviceStatus{Status: "disabled"}
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	u := "http://" + addr + "/_hazuki/health"
	return serviceStatus{Addr: addr, URL: u, Status: "disabled"}
}

func checkServiceStatus(ctx context.Context, port int) serviceStatus {
	return checkServiceStatusWithCookie(ctx, port, "")
}

func checkServiceStatusWithCookie(ctx context.Context, port int, sessionCookie string) serviceStatus {
	if port <= 0 || port > 65535 {
		return serviceStatus{Status: "disabled"}
	}

	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	u := "http://" + addr + "/_hazuki/health"

	checkCtx, cancel := context.WithTimeout(ctx, 650*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(checkCtx, http.MethodGet, u, nil)
	if err != nil {
		return serviceStatus{Addr: addr, URL: u, Status: "error", Error: err.Error()}
	}

	if strings.TrimSpace(sessionCookie) != "" {
		req.AddCookie(&http.Cookie{Name: cookieName, Value: sessionCookie})
	}

	client := &http.Client{
		Timeout: 650 * time.Millisecond,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	start := time.Now()
	resp, err := client.Do(req)
	latency := time.Since(start)
	if err != nil {
		return serviceStatus{
			Addr:      addr,
			URL:       u,
			Status:    "error",
			LatencyMS: latency.Milliseconds(),
			Error:     err.Error(),
		}
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		errMsg := fmt.Sprintf("http %d", resp.StatusCode)
		if b := strings.TrimSpace(string(body)); b != "" {
			errMsg += ": " + b
		}
		return serviceStatus{
			Addr:      addr,
			URL:       u,
			Status:    "error",
			LatencyMS: latency.Milliseconds(),
			Error:     errMsg,
		}
	}

	var payload struct {
		OK      bool   `json:"ok"`
		Service string `json:"service"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&payload); err != nil {
		return serviceStatus{
			Addr:      addr,
			URL:       u,
			Status:    "error",
			LatencyMS: latency.Milliseconds(),
			Error:     err.Error(),
		}
	}
	if !payload.OK {
		return serviceStatus{
			Addr:      addr,
			URL:       u,
			Service:   payload.Service,
			Status:    "error",
			LatencyMS: latency.Milliseconds(),
			Error:     "health returned ok=false",
		}
	}

	return serviceStatus{
		Addr:      addr,
		URL:       u,
		Service:   payload.Service,
		Status:    "ok",
		LatencyMS: latency.Milliseconds(),
	}
}

func sessionCookieValue(r *http.Request) string {
	if r == nil {
		return ""
	}
	c, err := r.Cookie(cookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

func getSQLiteMainDBPathAndSize(ctx context.Context, db *sql.DB) (path string, sizeBytes int64, err error) {
	rows, err := db.QueryContext(ctx, "PRAGMA database_list;")
	if err != nil {
		return "", 0, err
	}
	defer rows.Close()

	for rows.Next() {
		var seq int
		var name string
		var file string
		if err := rows.Scan(&seq, &name, &file); err != nil {
			return "", 0, err
		}
		if name == "main" {
			path = file
			break
		}
	}
	if err := rows.Err(); err != nil {
		return "", 0, err
	}
	if strings.TrimSpace(path) == "" {
		return "", 0, errors.New("database path is empty")
	}

	st, err := os.Stat(path)
	if err != nil {
		return path, 0, err
	}
	return path, st.Size(), nil
}

func formatBytes(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}

	const unit = 1024
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	suffixes := []string{"KB", "MB", "GB", "TB", "PB", "EB"}
	suffix := "KB"
	if exp >= 0 && exp < len(suffixes) {
		suffix = suffixes[exp]
	}
	return fmt.Sprintf("%.1f %s", float64(n)/float64(div), suffix)
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func setSessionCookie(w http.ResponseWriter, token string, ttlSeconds int, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    token,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   secure,
		Path:     "/",
		MaxAge:   ttlSeconds,
	})
}

func clearSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   secure,
		Path:     "/",
		MaxAge:   -1,
	})
}

func normalizePath(value string) string {
	s := strings.TrimSpace(value)
	if s == "" {
		return "/"
	}
	if !strings.HasPrefix(s, "/") {
		s = "/" + s
	}
	if len(s) > 1 && strings.HasSuffix(s, "/") {
		s = strings.TrimSuffix(s, "/")
	}
	return s
}

func parseCSV(value string) []string {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return []string{}
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		s := strings.TrimSpace(p)
		if s == "" {
			continue
		}
		out = append(out, s)
	}
	return out
}

func parseBool(value string, fallback bool) bool {
	v := strings.TrimSpace(strings.ToLower(value))
	if v == "" {
		return fallback
	}
	switch v {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return fallback
	}
}

func parseStringMapJSON(raw string) (map[string]string, error) {
	if strings.TrimSpace(raw) == "" {
		return map[string]string{}, nil
	}
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return nil, err
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("must be a JSON object")
	}
	out := make(map[string]string, len(obj))
	for k, vv := range obj {
		if strings.TrimSpace(k) == "" {
			continue
		}
		out[k] = fmt.Sprint(vv)
	}
	return out, nil
}

func noteIfEmpty(note, fallback string) string {
	if strings.TrimSpace(note) == "" {
		return fallback
	}
	return note
}

func normalizeAdminTimeZoneSpec(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "auto", true
	}
	sl := strings.ToLower(s)
	switch sl {
	case "auto", "browser", "local":
		return "auto", true
	case "utc", "z":
		return "UTC", true
	}

	if off, ok := storage.ParseTimeZoneOffsetMinutes(s); ok {
		if off == 0 {
			return "UTC", true
		}
		if spec, ok := storage.FormatTimeZoneOffsetMinutes(off); ok {
			return spec, true
		}
	}

	return "", false
}

func parsePort(value string, fallback int) (int, error) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 65535 {
		return 0, errI18n("error.portRange")
	}
	return n, nil
}

const maxTTLSeconds = 315360000 // 10 years

func parseTTLSeconds(value string) (int, error) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > maxTTLSeconds {
		return 0, errI18n("error.ttlRange", maxTTLSeconds)
	}
	return n, nil
}

func parseTTLOverrides(raw string) (map[string]int, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}

	// Allow JSON object as an alternative format.
	if strings.HasPrefix(trimmed, "{") {
		var m map[string]int
		if err := json.Unmarshal([]byte(trimmed), &m); err != nil {
			return nil, errI18n("error.ttlOverridesJsonInvalid", err.Error())
		}
		out := make(map[string]int, len(m))
		for k, v := range m {
			ext := normalizeExtKey(k)
			if ext == "" {
				continue
			}
			if v < 1 || v > maxTTLSeconds {
				return nil, errI18n("error.ttlOverridesEntryRange", ext, maxTTLSeconds)
			}
			out[ext] = v
		}
		if len(out) == 0 {
			return nil, nil
		}
		return out, nil
	}

	lines := strings.Split(raw, "\n")
	out := map[string]int{}
	for i, line := range lines {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		if idx := strings.IndexByte(s, '#'); idx != -1 {
			s = strings.TrimSpace(s[:idx])
		}
		if s == "" {
			continue
		}

		sep := strings.IndexAny(s, "=:")
		if sep == -1 {
			return nil, errI18n("error.ttlOverridesLineFormat", i+1)
		}

		ext := normalizeExtKey(strings.TrimSpace(s[:sep]))
		if ext == "" {
			return nil, errI18n("error.ttlOverridesLineEmptyExt", i+1)
		}
		if ext == "default" {
			return nil, errI18n("error.ttlOverridesLineDefaultNotAllowed", i+1)
		}

		ttlRaw := strings.TrimSpace(s[sep+1:])
		n, err := strconv.Atoi(ttlRaw)
		if err != nil || n < 1 || n > maxTTLSeconds {
			return nil, errI18n("error.ttlOverridesLineRange", i+1, maxTTLSeconds)
		}
		out[ext] = n
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func normalizeExtKey(ext string) string {
	s := strings.ToLower(strings.TrimSpace(ext))
	s = strings.TrimPrefix(s, ".")
	return s
}

func formatTTLOverrides(m map[string]int) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		if strings.TrimSpace(k) == "" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(strconv.Itoa(m[k]))
	}
	return b.String()
}

func parseHostMappingJSON(raw string) (map[string]string, error) {
	if strings.TrimSpace(raw) == "" {
		return map[string]string{}, nil
	}
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return nil, err
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("must be a JSON object")
	}
	out := make(map[string]string, len(obj))
	for k, vv := range obj {
		host := strings.TrimSpace(k)
		if host == "" {
			continue
		}
		val, ok := vv.(string)
		if !ok {
			return nil, fmt.Errorf("HOST_MAPPING[%q] must be a string", host)
		}
		target := strings.TrimSpace(val)
		if target == "" {
			continue
		}
		if strings.Contains(host, "://") || strings.Contains(target, "://") {
			return nil, fmt.Errorf("HOST_MAPPING[%q] must be a domain (no http(s)://)", host)
		}
		out[host] = target
	}
	return out, nil
}

func normalizeHeaderName(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func isValidHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '!' || c == '#' || c == '$' || c == '%' || c == '&' || c == '\'' || c == '*' || c == '+' || c == '-' || c == '.' || c == '^' || c == '_' || c == '`' || c == '|' || c == '~':
		default:
			return false
		}
	}
	return true
}

func parseHeaderNamesCSVStrict(value string) ([]string, error) {
	names := parseCSV(value)
	out := make([]string, 0, len(names))
	seen := make(map[string]struct{}, len(names))
	for _, raw := range names {
		name := normalizeHeaderName(raw)
		if name == "" {
			continue
		}
		if !isValidHeaderName(name) {
			return nil, errI18n("error.workerSecretHeadersInvalid")
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out, nil
}

func mergeSecretHeaderMap(raw string, current map[string]string, clear bool) (map[string]string, error) {
	if clear {
		return map[string]string{}, nil
	}
	currentMap := current
	if currentMap == nil {
		currentMap = map[string]string{}
	}

	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return map[string]string{}, nil
	}

	var v any
	if err := json.Unmarshal([]byte(trimmed), &v); err != nil {
		return nil, errI18n("error.workerSecretHeaderMapJsonInvalid", err.Error())
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, errI18n("error.workerSecretHeaderMapNotObject")
	}

	out := map[string]string{}
	for rawName, rawValue := range obj {
		headerName := normalizeHeaderName(rawName)
		if headerName == "" {
			continue
		}
		if !isValidHeaderName(headerName) {
			return nil, errI18n("error.workerSecretHeaderMapInvalidHeader")
		}

		switch vv := rawValue.(type) {
		case string:
			if vv == "__SET__" {
				if cur, ok := currentMap[headerName]; ok && strings.TrimSpace(cur) != "" {
					out[headerName] = cur
				}
				continue
			}
			val := strings.TrimSpace(vv)
			if val == "" {
				continue
			}
			out[headerName] = val
		case nil:
			continue
		default:
			return nil, errI18n("error.workerSecretHeaderMapValueMustBeString")
		}
	}
	return out, nil
}
