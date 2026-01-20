package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type AppConfig struct {
	Version    int             `json:"version"`
	Ports      PortsConfig      `json:"ports"`
	Cdnjs      CdnjsConfig      `json:"cdnjs"`
	Git        GitConfig        `json:"git"`
	Torcherino TorcherinoConfig `json:"torcherino"`
}

type PortsConfig struct {
	Admin      int `json:"admin"`
	Torcherino int `json:"torcherino"`
	Cdnjs      int `json:"cdnjs"`
	Git        int `json:"git"`
}

type RedisConfig struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

type CdnjsConfig struct {
	AssetURL      string      `json:"assetUrl"`
	AllowedGhUsers []string   `json:"allowedGhUsers"`
	DefaultGhUser string      `json:"defaultGhUser"`
	Redis         RedisConfig `json:"redis"`
	DefaultTTLSeconds int            `json:"defaultTTLSeconds,omitempty"`
	CacheTTLSeconds   map[string]int `json:"cacheTTLSeconds,omitempty"`
}

type GitConfig struct {
	GithubToken      string            `json:"githubToken"`
	GithubAuthScheme string            `json:"githubAuthScheme"`

	Upstream       string `json:"upstream"`
	UpstreamMobile string `json:"upstreamMobile"`
	UpstreamPath   string `json:"upstreamPath"`
	HTTPS          bool   `json:"https"`

	DisableCache     bool   `json:"disableCache"`
	CacheControl     string `json:"cacheControl"`
	CacheControlMedia string `json:"cacheControlMedia"`
	CacheControlText  string `json:"cacheControlText"`

	CorsOrigin          string `json:"corsOrigin"`
	CorsAllowCredentials bool   `json:"corsAllowCredentials"`
	CorsExposeHeaders    string `json:"corsExposeHeaders"`

	BlockedRegions    []string          `json:"blockedRegions"`
	BlockedIpAddresses []string         `json:"blockedIpAddresses"`

	ReplaceDict map[string]string `json:"replaceDict"`
}

type TorcherinoConfig struct {
	DefaultTarget        string            `json:"defaultTarget"`
	HostMapping          map[string]string `json:"hostMapping"`
	WorkerSecretKey      string            `json:"workerSecretKey"`
	WorkerSecretHeaders  []string          `json:"workerSecretHeaders"`
	WorkerSecretHeaderMap map[string]string `json:"workerSecretHeaderMap"`
}

func DefaultConfigFromEnv(getEnv func(string) string, lookupEnv func(string) (string, bool)) (AppConfig, error) {
	cfg := AppConfig{
		Version: 1,
		Ports: PortsConfig{
			Admin:      3100,
			Torcherino: 3000,
			Cdnjs:      3001,
			Git:        3002,
		},
		Cdnjs: CdnjsConfig{
			AssetURL:      strings.TrimSpace(defaultString(getEnv("ASSET_URL"), "https://cdn.jsdelivr.net")),
			AllowedGhUsers: parseCSV(getEnv("ALLOWED_GH_USERS")),
			DefaultGhUser: strings.TrimSpace(getEnv("DEFAULT_GH_USER")),
			Redis: RedisConfig{
				Host: strings.TrimSpace(defaultString(getEnv("REDIS_HOST"), "redis")),
				Port: parsePort(getEnv("REDIS_PORT"), 6379),
			},
		},
		Git: GitConfig{
			GithubToken:      getEnv("GITHUB_TOKEN"),
			GithubAuthScheme: strings.TrimSpace(defaultString(getEnv("GITHUB_AUTH_SCHEME"), "token")),

			Upstream:       strings.TrimSpace(defaultString(getEnv("UPSTREAM"), "raw.githubusercontent.com")),
			UpstreamMobile: strings.TrimSpace(defaultString(getEnv("UPSTREAM_MOBILE"), defaultString(getEnv("UPSTREAM"), "raw.githubusercontent.com"))),
			UpstreamPath:   strings.TrimSpace(defaultString(getEnv("UPSTREAM_PATH"), "/XMZO/pic/main")),
			HTTPS:          parseBool(getEnv("UPSTREAM_HTTPS"), true),

			DisableCache:      parseBool(getEnv("DISABLE_CACHE"), false),
			CacheControl:      strings.TrimSpace(getEnv("CACHE_CONTROL")),
			CacheControlMedia: strings.TrimSpace(defaultString(getEnv("CACHE_CONTROL_MEDIA"), "public, max-age=43200000")),
			CacheControlText:  strings.TrimSpace(defaultString(getEnv("CACHE_CONTROL_TEXT"), "public, max-age=60")),

			CorsOrigin:           strings.TrimSpace(defaultString(getEnv("CORS_ORIGIN"), "*")),
			CorsAllowCredentials: parseBool(getEnv("CORS_ALLOW_CREDENTIALS"), false),
			CorsExposeHeaders: strings.TrimSpace(defaultString(
				getEnv("CORS_EXPOSE_HEADERS"),
				"Accept-Ranges, Content-Length, Content-Range, ETag, Cache-Control, Last-Modified",
			)),

			BlockedRegions: parseCSV(getEnv("BLOCKED_REGION")),
			ReplaceDict: map[string]string{
				"$upstream": "$custom_domain",
			},
		},
		Torcherino: TorcherinoConfig{
			DefaultTarget:   strings.TrimSpace(getEnv("DEFAULT_TARGET")),
			HostMapping:     map[string]string{},
			WorkerSecretKey: getEnv("WORKER_SECRET_KEY"),
			WorkerSecretHeaders: parseHeaderNamesCSV(getEnv("WORKER_SECRET_HEADERS")),
			WorkerSecretHeaderMap: map[string]string{},
		},
	}

	if v := strings.TrimSpace(getEnv("HOST_MAPPING")); v != "" {
		m, err := parseStringMapJSON(v)
		if err != nil {
			return AppConfig{}, fmt.Errorf("HOST_MAPPING: %w", err)
		}
		cfg.Torcherino.HostMapping = m
	}

	if v := strings.TrimSpace(getEnv("WORKER_SECRET_HEADER_MAP")); v != "" {
		m, err := parseStringMapJSON(v)
		if err != nil {
			return AppConfig{}, fmt.Errorf("WORKER_SECRET_HEADER_MAP: %w", err)
		}
		cfg.Torcherino.WorkerSecretHeaderMap = m
	}

	if v := strings.TrimSpace(getEnv("REPLACE_DICT")); v != "" {
		m, err := parseStringMapJSON(v)
		if err != nil {
			return AppConfig{}, fmt.Errorf("REPLACE_DICT: %w", err)
		}
		cfg.Git.ReplaceDict = m
	}

	if _, ok := lookupEnv("BLOCKED_IP_ADDRESS"); ok {
		cfg.Git.BlockedIpAddresses = parseCSV(getEnv("BLOCKED_IP_ADDRESS"))
	} else {
		cfg.Git.BlockedIpAddresses = []string{"0.0.0.0", "127.0.0.1"}
	}

	cfg.Git.BlockedRegions = normalizeUpper(cfg.Git.BlockedRegions)
	cfg.Git.BlockedIpAddresses = trimFilter(cfg.Git.BlockedIpAddresses)
	cfg.Cdnjs.AllowedGhUsers = trimFilter(cfg.Cdnjs.AllowedGhUsers)

	return cfg, cfg.Validate()
}

func (c AppConfig) Validate() error {
	if c.Version != 1 {
		return fmt.Errorf("unsupported version: %d", c.Version)
	}
	const maxTTLSeconds = 315360000 // 10 years
	for _, p := range []struct {
		name string
		val  int
	}{
		{"ports.admin", c.Ports.Admin},
		{"ports.torcherino", c.Ports.Torcherino},
		{"ports.cdnjs", c.Ports.Cdnjs},
		{"ports.git", c.Ports.Git},
		{"cdnjs.redis.port", c.Cdnjs.Redis.Port},
	} {
		if p.val < 1 || p.val > 65535 {
			return fmt.Errorf("%s must be 1-65535", p.name)
		}
	}
	if c.Cdnjs.DefaultTTLSeconds < 0 || c.Cdnjs.DefaultTTLSeconds > maxTTLSeconds {
		return fmt.Errorf("cdnjs.defaultTTLSeconds must be 0-%d", maxTTLSeconds)
	}
	for ext, ttl := range c.Cdnjs.CacheTTLSeconds {
		if strings.TrimSpace(ext) == "" {
			return errors.New("cdnjs.cacheTTLSeconds has empty extension key")
		}
		if ttl < 1 || ttl > maxTTLSeconds {
			return fmt.Errorf("cdnjs.cacheTTLSeconds[%q] must be 1-%d", ext, maxTTLSeconds)
		}
	}
	if strings.TrimSpace(c.Git.UpstreamPath) == "" {
		return errors.New("git.upstreamPath is required")
	}
	return nil
}

func parsePort(value string, fallback int) int {
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || n < 1 || n > 65535 {
		return fallback
	}
	return n
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

func parseHeaderNamesCSV(value string) []string {
	items := parseCSV(value)
	out := make([]string, 0, len(items))
	for _, it := range items {
		name := strings.ToLower(strings.TrimSpace(it))
		if name == "" {
			continue
		}
		if !isValidHeaderName(name) {
			continue
		}
		out = append(out, name)
	}
	return out
}

func isValidHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i += 1 {
		c := name[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'z':
		case c == '-':
		case c == '!':
		case c == '#':
		case c == '$':
		case c == '%':
		case c == '&':
		case c == '\'':
		case c == '*':
		case c == '+':
		case c == '.':
		case c == '^':
		case c == '_':
		case c == '`':
		case c == '|':
		case c == '~':
		default:
			return false
		}
	}
	return true
}

func parseStringMapJSON(raw string) (map[string]string, error) {
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
		if k == "" {
			continue
		}
		out[k] = fmt.Sprint(vv)
	}
	return out, nil
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func normalizeUpper(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		s := strings.ToUpper(strings.TrimSpace(v))
		if s == "" {
			continue
		}
		out = append(out, s)
	}
	return out
}

func trimFilter(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		s := strings.TrimSpace(v)
		if s == "" {
			continue
		}
		out = append(out, s)
	}
	return out
}
