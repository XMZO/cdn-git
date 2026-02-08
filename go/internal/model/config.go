package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

type AppConfig struct {
	Version      int                 `json:"version"`
	Ports        PortsConfig         `json:"ports"`
	Cdnjs        CdnjsConfig         `json:"cdnjs"`
	Git          GitConfig           `json:"git"`
	GitInstances []GitInstanceConfig `json:"gitInstances,omitempty"`
	Torcherino   TorcherinoConfig    `json:"torcherino"`
	Sakuya       SakuyaConfig        `json:"sakuya"`
	Patchouli    PatchouliConfig     `json:"patchouli"`
}

type PortsConfig struct {
	Admin      int `json:"admin"`
	Torcherino int `json:"torcherino"`
	Cdnjs      int `json:"cdnjs"`
	Git        int `json:"git"`
	Sakuya     int `json:"sakuya"`
	Patchouli  int `json:"patchouli"`
}

type RedisConfig struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

type CdnjsConfig struct {
	Disabled          bool           `json:"disabled,omitempty"`
	AssetURL          string         `json:"assetUrl"`
	AllowedGhUsers    []string       `json:"allowedGhUsers"`
	BlockedGhUsers    []string       `json:"blockedGhUsers,omitempty"`
	GhUserPolicy      string         `json:"ghUserPolicy,omitempty"` // allowlist (default) | denylist
	DefaultGhUser     string         `json:"defaultGhUser"`
	Redis             RedisConfig    `json:"redis"`
	DefaultTTLSeconds int            `json:"defaultTTLSeconds,omitempty"`
	CacheTTLSeconds   map[string]int `json:"cacheTTLSeconds,omitempty"`
}

type GitConfig struct {
	Disabled         bool   `json:"disabled,omitempty"`
	GithubToken      string `json:"githubToken"`
	GithubAuthScheme string `json:"githubAuthScheme"`

	Upstream       string `json:"upstream"`
	UpstreamMobile string `json:"upstreamMobile"`
	UpstreamPath   string `json:"upstreamPath"`
	HTTPS          bool   `json:"https"`

	DisableCache      bool   `json:"disableCache"`
	CacheControl      string `json:"cacheControl"`
	CacheControlMedia string `json:"cacheControlMedia"`
	CacheControlText  string `json:"cacheControlText"`

	CorsOrigin           string `json:"corsOrigin"`
	CorsAllowCredentials bool   `json:"corsAllowCredentials"`
	CorsExposeHeaders    string `json:"corsExposeHeaders"`

	BlockedRegions     []string `json:"blockedRegions"`
	BlockedIpAddresses []string `json:"blockedIpAddresses"`

	ReplaceDict map[string]string `json:"replaceDict"`
}

type GitInstanceConfig struct {
	ID   string    `json:"id"`
	Name string    `json:"name,omitempty"`
	Port int       `json:"port"`
	Git  GitConfig `json:"git"`
}

type TorcherinoConfig struct {
	Disabled              bool                       `json:"disabled,omitempty"`
	DefaultTarget         string                     `json:"defaultTarget"`
	HostMapping           map[string]string          `json:"hostMapping"`
	WorkerSecretKey       string                     `json:"workerSecretKey"`
	WorkerSecretHeaders   []string                   `json:"workerSecretHeaders"`
	WorkerSecretHeaderMap map[string]string          `json:"workerSecretHeaderMap"`
	ForwardClientIP       bool                       `json:"forwardClientIp,omitempty"`
	TrustCfConnectingIP   bool                       `json:"trustCfConnectingIp,omitempty"`
	RedisCache            TorcherinoRedisCacheConfig `json:"redisCache,omitempty"`
}

type TorcherinoRedisCacheConfig struct {
	Enabled bool `json:"enabled,omitempty"`

	// MaxBodyBytes limits the cached response size. 0 means "use built-in default".
	MaxBodyBytes int `json:"maxBodyBytes,omitempty"`

	// DefaultTTLSeconds is used when upstream has no explicit max-age.
	// 0 means "only cache when upstream max-age is present".
	DefaultTTLSeconds int `json:"defaultTTLSeconds,omitempty"`

	// MaxTTLSeconds caps the cache TTL. 0 means "use built-in default".
	MaxTTLSeconds int `json:"maxTTLSeconds,omitempty"`
}

type SakuyaConfig struct {
	// Legacy: originally used as a single switch for Sakuya features.
	// Now treated as an alias for "oplist disabled" for backward compatibility.
	Disabled bool `json:"disabled,omitempty"`

	Oplist SakuyaOplist `json:"oplist"`

	// Additional OpenList instances routed by URL prefix (e.g. /op1/...).
	// The default instance uses `oplist` and matches requests without a prefix.
	Instances []SakuyaOplistInstance `json:"instances,omitempty"`
}

type SakuyaOplist struct {
	Disabled bool `json:"disabled,omitempty"`

	Address   string `json:"address"`
	Token     string `json:"token"`
	PublicURL string `json:"publicUrl,omitempty"`
}

type SakuyaOplistInstance struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`

	Disabled bool `json:"disabled,omitempty"`

	// URL path prefix segment used to select this instance, without slashes.
	// Example: "op1" matches /op1/...
	Prefix string `json:"prefix"`

	Address   string `json:"address"`
	Token     string `json:"token"`
	PublicURL string `json:"publicUrl,omitempty"`
}

type PatchouliConfig struct {
	Disabled bool `json:"disabled,omitempty"`

	// kind: "dataset" | "model" | "space"
	Kind string `json:"kind,omitempty"`

	// Repo in the form "username/repo".
	Repo string `json:"repo"`

	// Revision: branch/tag/commit. Defaults to "main".
	Revision string `json:"revision,omitempty"`

	// Token: HuggingFace access token (hf_...). Used as "Authorization: Bearer <token>".
	Token string `json:"token"`

	// Optional access key gate. If set, clients must provide it via query (?key=) or header (X-Patchouli-Key).
	AccessKey string `json:"accessKey,omitempty"`

	// When true, force "Cache-Control: no-store".
	DisableCache bool `json:"disableCache,omitempty"`

	// Optional list of allowed redirect host suffixes (e.g. ".huggingface.co").
	AllowedRedirectHostSuffixes []string `json:"allowedRedirectHostSuffixes,omitempty"`
}

func DefaultConfigFromEnv(getEnv func(string) string, lookupEnv func(string) (string, bool)) (AppConfig, error) {
	oplistAddr := strings.TrimSpace(getEnv("OPLIST_ADDRESS"))
	oplistToken := strings.TrimSpace(getEnv("OPLIST_TOKEN"))
	oplistEnabled := oplistAddr != "" && oplistToken != ""
	patchRepo := strings.TrimSpace(getEnv("PATCHOULI_REPO"))
	patchEnabled := patchRepo != ""

	cfg := AppConfig{
		Version: 1,
		Ports: PortsConfig{
			Admin:      3100,
			Torcherino: 3000,
			Cdnjs:      3001,
			Git:        3002,
			Sakuya:     3200,
			Patchouli:  3201,
		},
		Cdnjs: CdnjsConfig{
			AssetURL:       strings.TrimSpace(defaultString(getEnv("ASSET_URL"), "https://cdn.jsdelivr.net")),
			AllowedGhUsers: parseCSV(getEnv("ALLOWED_GH_USERS")),
			BlockedGhUsers: parseCSV(getEnv("BLOCKED_GH_USERS")),
			GhUserPolicy:   strings.TrimSpace(getEnv("GH_USER_POLICY")),
			DefaultGhUser:  strings.TrimSpace(getEnv("DEFAULT_GH_USER")),
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
			DefaultTarget:         strings.TrimSpace(getEnv("DEFAULT_TARGET")),
			HostMapping:           map[string]string{},
			WorkerSecretKey:       getEnv("WORKER_SECRET_KEY"),
			WorkerSecretHeaders:   parseHeaderNamesCSV(getEnv("WORKER_SECRET_HEADERS")),
			WorkerSecretHeaderMap: map[string]string{},
			ForwardClientIP:       parseBool(getEnv("TORCHERINO_FORWARD_CLIENT_IP"), false),
			TrustCfConnectingIP:   parseBool(getEnv("TORCHERINO_TRUST_CF_CONNECTING_IP"), false),
		},
		Sakuya: SakuyaConfig{
			Disabled: false,
			Oplist: SakuyaOplist{
				Disabled:  !oplistEnabled,
				Address:   oplistAddr,
				Token:     oplistToken,
				PublicURL: strings.TrimSpace(getEnv("OPLIST_PUBLIC_URL")),
			},
		},
		Patchouli: PatchouliConfig{
			Disabled:                    !patchEnabled || parseBool(getEnv("PATCHOULI_DISABLED"), false),
			Kind:                        strings.TrimSpace(defaultString(getEnv("PATCHOULI_KIND"), "dataset")),
			Repo:                        patchRepo,
			Revision:                    strings.TrimSpace(defaultString(getEnv("PATCHOULI_REVISION"), "main")),
			Token:                       getEnv("PATCHOULI_TOKEN"),
			AccessKey:                   getEnv("PATCHOULI_ACCESS_KEY"),
			DisableCache:                parseBool(getEnv("PATCHOULI_DISABLE_CACHE"), true),
			AllowedRedirectHostSuffixes: trimFilter(parseCSV(getEnv("PATCHOULI_ALLOWED_REDIRECT_HOST_SUFFIXES"))),
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
		cfg.Git.ReplaceDict = normalizeGitReplaceDictPlaceholders(m)
	}

	if _, ok := lookupEnv("BLOCKED_IP_ADDRESS"); ok {
		cfg.Git.BlockedIpAddresses = parseCSV(getEnv("BLOCKED_IP_ADDRESS"))
	} else {
		cfg.Git.BlockedIpAddresses = []string{"0.0.0.0", "127.0.0.1"}
	}

	cfg.Git.BlockedRegions = normalizeUpper(cfg.Git.BlockedRegions)
	cfg.Git.BlockedIpAddresses = trimFilter(cfg.Git.BlockedIpAddresses)
	cfg.Cdnjs.AllowedGhUsers = trimFilter(cfg.Cdnjs.AllowedGhUsers)
	cfg.Cdnjs.BlockedGhUsers = trimFilter(cfg.Cdnjs.BlockedGhUsers)

	return cfg, cfg.Validate()
}

func normalizeGitReplaceDictPlaceholders(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[normalizeGitReplaceDictToken(k)] = normalizeGitReplaceDictToken(v)
	}
	return out
}

func normalizeGitReplaceDictToken(s string) string {
	switch s {
	case "$$upstream":
		return "$upstream"
	case "$$custom_domain":
		return "$custom_domain"
	default:
		return s
	}
}

func (c AppConfig) Validate() error {
	if c.Version != 1 {
		return fmt.Errorf("unsupported version: %d", c.Version)
	}
	const maxTTLSeconds = 315360000                      // 10 years
	const maxTorcherinoCacheBodyBytes = 10 * 1024 * 1024 // 10 MiB
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
	// Backward-compatibility: older configs won't have ports.sakuya yet.
	if c.Ports.Sakuya != 0 && (c.Ports.Sakuya < 1 || c.Ports.Sakuya > 65535) {
		return fmt.Errorf("%s must be 1-65535", "ports.sakuya")
	}
	// Backward-compatibility: older configs won't have ports.patchouli yet.
	if c.Ports.Patchouli != 0 && (c.Ports.Patchouli < 1 || c.Ports.Patchouli > 65535) {
		return fmt.Errorf("%s must be 1-65535", "ports.patchouli")
	}

	// Prevent port conflicts among enabled services/instances.
	usedPorts := map[int]string{
		c.Ports.Admin: "admin",
	}
	addPort := func(port int, name string) error {
		if port < 1 || port > 65535 {
			return nil
		}
		if prev, ok := usedPorts[port]; ok {
			return fmt.Errorf("port conflict: %d used by %s and %s", port, prev, name)
		}
		usedPorts[port] = name
		return nil
	}

	// Sakuya (OpenList/Oplist) can have multiple instances. The default instance uses `sakuya.oplist`.
	defaultOplistConfigured := strings.TrimSpace(c.Sakuya.Oplist.Address) != "" ||
		strings.TrimSpace(c.Sakuya.Oplist.Token) != "" ||
		strings.TrimSpace(c.Sakuya.Oplist.PublicURL) != ""
	defaultOplistEnabled := !c.Sakuya.Disabled && !c.Sakuya.Oplist.Disabled && defaultOplistConfigured

	anyInstanceEnabled := false
	for _, inst := range c.Sakuya.Instances {
		instConfigured := strings.TrimSpace(inst.Address) != "" ||
			strings.TrimSpace(inst.Token) != "" ||
			strings.TrimSpace(inst.PublicURL) != ""
		if !c.Sakuya.Disabled && !inst.Disabled && instConfigured {
			anyInstanceEnabled = true
			break
		}
	}
	sakuyaEnabled := defaultOplistEnabled || anyInstanceEnabled
	patchouliEnabled := !c.Patchouli.Disabled && strings.TrimSpace(c.Patchouli.Repo) != ""
	if !c.Torcherino.Disabled {
		if err := addPort(c.Ports.Torcherino, "torcherino"); err != nil {
			return err
		}
	}
	if !c.Cdnjs.Disabled {
		if err := addPort(c.Ports.Cdnjs, "cdnjs"); err != nil {
			return err
		}
	}
	if !c.Git.Disabled {
		if err := addPort(c.Ports.Git, "git(default)"); err != nil {
			return err
		}
	}
	if sakuyaEnabled {
		port := c.Ports.Sakuya
		if port == 0 {
			port = 3200
		}
		if err := addPort(port, "sakuya"); err != nil {
			return err
		}
	}
	if patchouliEnabled {
		port := c.Ports.Patchouli
		if port == 0 {
			port = 3201
		}
		if err := addPort(port, "patchouli"); err != nil {
			return err
		}
	}
	ghUserPolicy := strings.ToLower(strings.TrimSpace(c.Cdnjs.GhUserPolicy))
	if ghUserPolicy != "" && ghUserPolicy != "allowlist" && ghUserPolicy != "denylist" {
		return errors.New("cdnjs.ghUserPolicy must be 'allowlist' or 'denylist'")
	}
	if c.Torcherino.RedisCache.MaxBodyBytes < 0 || c.Torcherino.RedisCache.MaxBodyBytes > maxTorcherinoCacheBodyBytes {
		return fmt.Errorf("torcherino.redisCache.maxBodyBytes must be 0-%d", maxTorcherinoCacheBodyBytes)
	}
	if c.Torcherino.RedisCache.DefaultTTLSeconds < 0 || c.Torcherino.RedisCache.DefaultTTLSeconds > maxTTLSeconds {
		return fmt.Errorf("torcherino.redisCache.defaultTTLSeconds must be 0-%d", maxTTLSeconds)
	}
	if c.Torcherino.RedisCache.MaxTTLSeconds < 0 || c.Torcherino.RedisCache.MaxTTLSeconds > maxTTLSeconds {
		return fmt.Errorf("torcherino.redisCache.maxTTLSeconds must be 0-%d", maxTTLSeconds)
	}
	if c.Torcherino.RedisCache.MaxTTLSeconds > 0 && c.Torcherino.RedisCache.DefaultTTLSeconds > 0 &&
		c.Torcherino.RedisCache.MaxTTLSeconds < c.Torcherino.RedisCache.DefaultTTLSeconds {
		return errors.New("torcherino.redisCache.maxTTLSeconds must be >= torcherino.redisCache.defaultTTLSeconds")
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
	if !c.Git.Disabled && strings.TrimSpace(c.Git.UpstreamPath) == "" {
		return errors.New("git.upstreamPath is required")
	}

	seenGitIDs := map[string]struct{}{}
	for i, inst := range c.GitInstances {
		id := strings.TrimSpace(inst.ID)
		if id == "" {
			return fmt.Errorf("gitInstances[%d].id is required", i)
		}
		if strings.EqualFold(id, "default") {
			return fmt.Errorf("gitInstances[%d].id cannot be 'default'", i)
		}
		if _, ok := seenGitIDs[strings.ToLower(id)]; ok {
			return fmt.Errorf("gitInstances[%d].id duplicated: %q", i, id)
		}
		seenGitIDs[strings.ToLower(id)] = struct{}{}

		if inst.Port < 1 || inst.Port > 65535 {
			return fmt.Errorf("gitInstances[%q].port must be 1-65535", id)
		}
		if !inst.Git.Disabled {
			if err := addPort(inst.Port, "gitInstances."+id); err != nil {
				return err
			}
		}

		if !inst.Git.Disabled && strings.TrimSpace(inst.Git.UpstreamPath) == "" {
			return fmt.Errorf("gitInstances[%q].git.upstreamPath is required", id)
		}
	}

	if defaultOplistEnabled {
		if strings.TrimSpace(c.Sakuya.Oplist.Token) == "" {
			return errors.New("sakuya.oplist.token is required")
		}

		addr := strings.TrimSpace(c.Sakuya.Oplist.Address)
		if addr == "" {
			return errors.New("sakuya.oplist.address is required")
		}
		u, err := url.Parse(addr)
		if err != nil {
			return errors.New("sakuya.oplist.address is invalid")
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return errors.New("sakuya.oplist.address must start with http:// or https://")
		}
		if strings.TrimSpace(u.Host) == "" {
			return errors.New("sakuya.oplist.address host is empty")
		}

		if strings.TrimSpace(c.Sakuya.Oplist.PublicURL) != "" {
			pu, err := url.Parse(strings.TrimSpace(c.Sakuya.Oplist.PublicURL))
			if err != nil {
				return errors.New("sakuya.oplist.publicUrl is invalid")
			}
			if pu.Scheme != "http" && pu.Scheme != "https" {
				return errors.New("sakuya.oplist.publicUrl must start with http:// or https://")
			}
			if strings.TrimSpace(pu.Host) == "" {
				return errors.New("sakuya.oplist.publicUrl host is empty")
			}
		}
	}

	seenSakuyaIDs := map[string]struct{}{}
	for i, inst := range c.Sakuya.Instances {
		id := strings.TrimSpace(inst.ID)
		if id == "" {
			return fmt.Errorf("sakuya.instances[%d].id is required", i)
		}
		if strings.EqualFold(id, "default") {
			return fmt.Errorf("sakuya.instances[%d].id cannot be 'default'", i)
		}
		if _, ok := seenSakuyaIDs[strings.ToLower(id)]; ok {
			return fmt.Errorf("sakuya.instances[%d].id duplicated: %q", i, id)
		}
		seenSakuyaIDs[strings.ToLower(id)] = struct{}{}

		prefix := strings.TrimSpace(inst.Prefix)
		if prefix == "" {
			return fmt.Errorf("sakuya.instances[%q].prefix is required", id)
		}
		if strings.EqualFold(prefix, "_hazuki") {
			return fmt.Errorf("sakuya.instances[%q].prefix is reserved", id)
		}
		if strings.Contains(prefix, "/") || strings.Contains(prefix, "\\") {
			return fmt.Errorf("sakuya.instances[%q].prefix must not contain slashes", id)
		}
		if !isValidPathPrefixSegment(prefix) {
			return fmt.Errorf("sakuya.instances[%q].prefix is invalid", id)
		}

		instConfigured := strings.TrimSpace(inst.Address) != "" ||
			strings.TrimSpace(inst.Token) != "" ||
			strings.TrimSpace(inst.PublicURL) != ""
		instEnabled := !c.Sakuya.Disabled && !inst.Disabled && instConfigured
		if !instEnabled {
			continue
		}

		if strings.TrimSpace(inst.Token) == "" {
			return fmt.Errorf("sakuya.instances[%q].token is required", id)
		}

		addr := strings.TrimSpace(inst.Address)
		if addr == "" {
			return fmt.Errorf("sakuya.instances[%q].address is required", id)
		}
		u, err := url.Parse(addr)
		if err != nil {
			return fmt.Errorf("sakuya.instances[%q].address is invalid", id)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("sakuya.instances[%q].address must start with http:// or https://", id)
		}
		if strings.TrimSpace(u.Host) == "" {
			return fmt.Errorf("sakuya.instances[%q].address host is empty", id)
		}

		if strings.TrimSpace(inst.PublicURL) != "" {
			pu, err := url.Parse(strings.TrimSpace(inst.PublicURL))
			if err != nil {
				return fmt.Errorf("sakuya.instances[%q].publicUrl is invalid", id)
			}
			if pu.Scheme != "http" && pu.Scheme != "https" {
				return fmt.Errorf("sakuya.instances[%q].publicUrl must start with http:// or https://", id)
			}
			if strings.TrimSpace(pu.Host) == "" {
				return fmt.Errorf("sakuya.instances[%q].publicUrl host is empty", id)
			}
		}
	}

	if patchouliEnabled {
		kind := strings.ToLower(strings.TrimSpace(c.Patchouli.Kind))
		if kind == "" {
			kind = "dataset"
		}
		switch kind {
		case "dataset", "model", "space":
			// ok
		default:
			return errors.New("patchouli.kind must be 'dataset', 'model' or 'space'")
		}

		if strings.TrimSpace(c.Patchouli.Repo) == "" {
			return errors.New("patchouli.repo is required")
		}

		for _, suf := range c.Patchouli.AllowedRedirectHostSuffixes {
			s := strings.TrimSpace(suf)
			if s == "" {
				return errors.New("patchouli.allowedRedirectHostSuffixes has empty entry")
			}
			if strings.Contains(s, "/") || strings.Contains(s, "\\") || strings.Contains(s, ":") {
				return errors.New("patchouli.allowedRedirectHostSuffixes entries must be host suffixes (no scheme/path)")
			}
		}
	}
	return nil
}

func isValidPathPrefixSegment(s string) bool {
	// Intentionally strict: this becomes part of the public URL path.
	if strings.TrimSpace(s) == "" {
		return false
	}
	if len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c == '-':
		case c == '_':
		case c == '.':
		default:
			return false
		}
	}
	return true
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
