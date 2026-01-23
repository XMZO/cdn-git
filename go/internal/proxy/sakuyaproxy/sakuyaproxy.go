package sakuyaproxy

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"hazuki-go/internal/model"
)

type RuntimeConfig struct {
	Host string
	Port int

	OplistAddress   string
	OplistToken     string
	OplistPublicURL string
}

func BuildRuntimeConfig(cfg model.AppConfig) (RuntimeConfig, error) {
	port := cfg.Ports.Sakuya
	if port == 0 {
		port = 3200
	}

	opAddr := strings.TrimSpace(cfg.Sakuya.Oplist.Address)
	if opAddr != "" {
		opAddr = strings.TrimRight(opAddr, "/")
		u, err := url.Parse(opAddr)
		if err != nil {
			return RuntimeConfig{}, err
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return RuntimeConfig{}, errors.New("sakuya.oplist.address must start with http:// or https://")
		}
		if strings.TrimSpace(u.Host) == "" {
			return RuntimeConfig{}, errors.New("sakuya.oplist.address host is empty")
		}
	}

	publicURL := strings.TrimSpace(cfg.Sakuya.Oplist.PublicURL)
	if publicURL != "" {
		publicURL = strings.TrimRight(publicURL, "/")
		u, err := url.Parse(publicURL)
		if err != nil {
			return RuntimeConfig{}, err
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return RuntimeConfig{}, errors.New("sakuya.oplist.publicUrl must start with http:// or https://")
		}
		if strings.TrimSpace(u.Host) == "" {
			return RuntimeConfig{}, errors.New("sakuya.oplist.publicUrl host is empty")
		}
	}

	return RuntimeConfig{
		Host: "0.0.0.0",
		Port: port,

		OplistAddress:   opAddr,
		OplistToken:     cfg.Sakuya.Oplist.Token,
		OplistPublicURL: publicURL,
	}, nil
}

type Handler struct {
	getRuntime func() RuntimeConfig

	apiClient      *http.Client
	downloadClient *http.Client

	maxRedirects int
}

type HandlerOptions struct {
	GetRuntime func() RuntimeConfig

	// Optional. If nil, sensible defaults are used.
	APIClient      *http.Client
	DownloadClient *http.Client

	MaxRedirects int
}

func NewHandler(opts HandlerOptions) *Handler {
	getRuntime := opts.GetRuntime
	if getRuntime == nil {
		getRuntime = func() RuntimeConfig { return RuntimeConfig{} }
	}

	return &Handler{
		getRuntime:     getRuntime,
		apiClient:      defaultAPIClient(opts.APIClient),
		downloadClient: defaultDownloadClient(opts.DownloadClient),
		maxRedirects:   defaultInt(opts.MaxRedirects, 10),
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	runtime := RuntimeConfig{}
	if h.getRuntime != nil {
		runtime = h.getRuntime()
	}
	h.serveHTTP(w, r, runtime, 0)
}

func (h *Handler) serveHTTP(w http.ResponseWriter, r *http.Request, runtime RuntimeConfig, depth int) {
	if r == nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		// continue
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Health (loopback only).
	if (r.Method == http.MethodGet || r.Method == http.MethodHead) && r.URL.Path == "/_hazuki/health" {
		if !isLoopbackRemoteAddr(r.RemoteAddr) {
			http.NotFound(w, r)
			return
		}
		h.writeHealth(w, r, runtime)
		return
	}

	if r.Method == http.MethodOptions {
		writeCORSPreflight(w, r)
		return
	}

	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		origin = "*"
	}

	// If config isn't ready, behave like a disabled/broken upstream.
	if strings.TrimSpace(runtime.OplistAddress) == "" || strings.TrimSpace(runtime.OplistToken) == "" {
		writeJSONWithStatus(w, r, origin, http.StatusBadGateway, map[string]any{"code": 502, "message": "oplist is not configured"})
		return
	}

	decodedPath, err := url.PathUnescape(r.URL.EscapedPath())
	if err != nil {
		writeJSON(w, r, origin, map[string]any{"code": 400, "message": "path invalid"})
		return
	}

	sign := r.URL.Query().Get("sign")
	if msg := verifySign(decodedPath, sign, runtime.OplistToken, time.Now()); msg != "" {
		// Keep Worker behavior: HTTP 200 with app-level code.
		writeJSON(w, r, origin, map[string]any{"code": 401, "message": msg})
		return
	}

	link, err := h.fetchLink(r.Context(), runtime, decodedPath)
	if err != nil {
		writeJSONWithStatus(w, r, origin, http.StatusBadGateway, map[string]any{"code": 502, "message": err.Error()})
		return
	}
	if link.Code != 200 {
		// Keep Worker behavior: pass through JSON as-is (still HTTP 200).
		writeJSON(w, r, origin, link)
		return
	}
	if strings.TrimSpace(link.Data.URL) == "" {
		writeJSONWithStatus(w, r, origin, http.StatusBadGateway, map[string]any{"code": 502, "message": "oplist: empty url"})
		return
	}

	upReq, err := http.NewRequestWithContext(r.Context(), r.Method, link.Data.URL, nil)
	if err != nil {
		writeJSONWithStatus(w, r, origin, http.StatusBadGateway, map[string]any{"code": 502, "message": "bad gateway"})
		return
	}
	upReq.Header = cloneRequestHeaders(r.Header)
	upReq.Header.Set("Accept-Encoding", "identity")
	applyLinkHeaders(upReq.Header, link.Data.Header)

	resp, err := h.doWithRedirects(upReq, runtime, r, w, depth)
	if err != nil {
		writeJSONWithStatus(w, r, origin, http.StatusBadGateway, map[string]any{"code": 502, "message": err.Error()})
		return
	}
	if resp == nil {
		// Internal redirect handled by recursion.
		return
	}
	defer func() { _ = resp.Body.Close() }()

	headers := w.Header()
	copyResponseHeaders(headers, resp.Header)

	// Worker behavior: delete some upstream headers.
	headers.Del("set-cookie")
	headers.Del("pragma")
	headers.Del("expires")
	headers.Del("cache-control")
	headers.Del("x-guploader-uploadid")
	headers.Del("x-goog-hash")
	headers.Del("date")
	headers.Del("vary")

	headers.Set("access-control-allow-origin", origin)
	headers.Set("accept-ranges", "bytes")
	headers.Set("vary", "Origin")

	if (r.Method == http.MethodGet || r.Method == http.MethodHead) && resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		headers.Set("cache-control", "public, max-age=31536000, immutable")
	} else {
		headers.Set("cache-control", "no-store")
	}

	w.WriteHeader(resp.StatusCode)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = io.Copy(w, resp.Body)
}

func (h *Handler) writeHealth(w http.ResponseWriter, r *http.Request, runtime RuntimeConfig) {
	payload := map[string]any{
		"ok":      true,
		"service": "sakuya",
		"host":    runtime.Host,
		"port":    runtime.Port,
		"oplist": map[string]any{
			"address":        runtime.OplistAddress,
			"tokenSet":       strings.TrimSpace(runtime.OplistToken) != "",
			"publicUrl":      runtime.OplistPublicURL,
			"publicUrlIsSet": strings.TrimSpace(runtime.OplistPublicURL) != "",
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

type linkResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message,omitempty"`
	Data    struct {
		URL    string              `json:"url"`
		Header map[string][]string `json:"header,omitempty"`
	} `json:"data"`
}

func (h *Handler) fetchLink(ctx context.Context, runtime RuntimeConfig, path string) (linkResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	payload := struct {
		Path string `json:"path"`
	}{Path: path}
	body, _ := json.Marshal(payload)

	u := runtime.OplistAddress + "/api/fs/link"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return linkResponse{}, err
	}
	req.Header.Set("content-type", "application/json;charset=UTF-8")
	req.Header.Set("authorization", runtime.OplistToken)

	resp, err := h.apiClient.Do(req)
	if err != nil {
		return linkResponse{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return linkResponse{}, err
	}
	if len(raw) == 0 {
		return linkResponse{}, errors.New("oplist: empty api response")
	}

	var out linkResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return linkResponse{}, err
	}
	return out, nil
}

func (h *Handler) doWithRedirects(upReq *http.Request, runtime RuntimeConfig, originalReq *http.Request, w http.ResponseWriter, depth int) (*http.Response, error) {
	if upReq == nil {
		return nil, errors.New("bad gateway")
	}

	req := upReq
	for i := 0; i <= h.maxRedirects; i++ {
		resp, err := h.downloadClient.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			return resp, nil
		}

		loc := strings.TrimSpace(resp.Header.Get("Location"))
		if loc == "" {
			return resp, nil
		}

		_ = resp.Body.Close()

		nextURL, err := resolveRedirect(resp.Request.URL, loc)
		if err != nil {
			return nil, err
		}

		if isSelfRedirect(nextURL, runtime, originalReq) {
			if depth >= 8 {
				return nil, errors.New("redirect loop")
			}
			h.serveHTTP(w, cloneIncomingRequest(originalReq, nextURL), runtime, depth+1)
			return nil, nil
		}

		nextReq, err := http.NewRequestWithContext(req.Context(), req.Method, nextURL.String(), nil)
		if err != nil {
			return nil, err
		}
		nextReq.Header = req.Header.Clone()
		req = nextReq
	}
	return nil, errors.New("too many redirects")
}

func resolveRedirect(base *url.URL, location string) (*url.URL, error) {
	u, err := url.Parse(location)
	if err != nil {
		return nil, err
	}
	if base == nil {
		return u, nil
	}
	return base.ResolveReference(u), nil
}

func cloneIncomingRequest(orig *http.Request, u *url.URL) *http.Request {
	if orig == nil {
		return &http.Request{Method: http.MethodGet, URL: u}
	}
	r := orig.Clone(orig.Context())
	// Keep headers/body/remote addr, but change path/query/host.
	if u != nil {
		r.URL = &url.URL{
			Path:     u.Path,
			RawPath:  u.RawPath,
			RawQuery: u.RawQuery,
			Fragment: u.Fragment,
		}
		if strings.TrimSpace(u.Host) != "" {
			r.Host = u.Host
		}
	}
	return r
}

func isSelfRedirect(u *url.URL, runtime RuntimeConfig, r *http.Request) bool {
	if u == nil {
		return false
	}
	host := strings.ToLower(strings.TrimSpace(u.Host))
	if host == "" {
		return false
	}

	if strings.TrimSpace(runtime.OplistPublicURL) != "" {
		pu, err := url.Parse(runtime.OplistPublicURL)
		if err == nil && pu != nil && strings.EqualFold(pu.Host, u.Host) {
			return true
		}
	}

	if r != nil {
		reqOrigin := buildRequestOrigin(r)
		if reqOrigin != "" {
			ou, err := url.Parse(reqOrigin)
			if err == nil && ou != nil && strings.EqualFold(ou.Host, u.Host) {
				return true
			}
		}
	}

	return false
}

func buildRequestOrigin(r *http.Request) string {
	if r == nil {
		return ""
	}
	proto := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]))
	if proto == "" {
		if r.TLS != nil {
			proto = "https"
		} else {
			proto = "http"
		}
	}
	host := strings.TrimSpace(r.Host)
	if host == "" {
		host = "localhost"
	}
	return proto + "://" + host
}

func verifySign(path string, sign string, token string, now time.Time) string {
	sign = strings.TrimSpace(sign)
	if sign == "" {
		return "expire missing"
	}
	parts := strings.Split(sign, ":")
	last := strings.TrimSpace(parts[len(parts)-1])
	if last == "" {
		return "expire missing"
	}
	expire, err := strconv.ParseInt(last, 10, 64)
	if err != nil {
		return "expire invalid"
	}
	if expire > 0 && expire < now.UTC().Unix() {
		return "expire expired"
	}

	expected := hmacSha256Sign(path, expire, token)
	if len(sign) != len(expected) || subtle.ConstantTimeCompare([]byte(sign), []byte(expected)) != 1 {
		return "sign mismatch"
	}
	return ""
}

func hmacSha256Sign(data string, expire int64, token string) string {
	mac := hmac.New(sha256.New, []byte(token))
	_, _ = mac.Write([]byte(data))
	_, _ = mac.Write([]byte(":"))
	_, _ = mac.Write([]byte(strconv.FormatInt(expire, 10)))
	sum := mac.Sum(nil)

	b64 := base64.URLEncoding.EncodeToString(sum)
	return b64 + ":" + strconv.FormatInt(expire, 10)
}

func applyLinkHeaders(dst http.Header, src map[string][]string) {
	if dst == nil || len(src) == 0 {
		return
	}
	for k, vals := range src {
		key := strings.TrimSpace(k)
		if key == "" {
			continue
		}
		for _, v := range vals {
			dst.Set(key, v)
		}
	}
}

func writeCORSPreflight(w http.ResponseWriter, r *http.Request) {
	corsHeaders := map[string]string{
		"access-control-allow-origin":  "*",
		"access-control-allow-methods": "GET,HEAD,POST,OPTIONS",
		"access-control-max-age":       "86400",
	}
	if r != nil && r.Header.Get("Origin") != "" && r.Header.Get("Access-Control-Request-Method") != "" {
		for k, v := range corsHeaders {
			w.Header().Set(k, v)
		}
		w.Header().Set("access-control-allow-headers", r.Header.Get("Access-Control-Request-Headers"))
		w.WriteHeader(http.StatusOK)
		return
	}
	w.Header().Set("allow", "GET, HEAD, POST, OPTIONS")
	w.WriteHeader(http.StatusOK)
}

func writeJSON(w http.ResponseWriter, r *http.Request, origin string, payload any) {
	writeJSONWithStatus(w, r, origin, http.StatusOK, payload)
}

func writeJSONWithStatus(w http.ResponseWriter, r *http.Request, origin string, status int, payload any) {
	b, _ := json.Marshal(payload)
	w.Header().Set("content-type", "application/json; charset=utf-8")
	w.Header().Set("access-control-allow-origin", origin)
	w.Header().Set("vary", "Origin")
	w.Header().Set("cache-control", "no-store")
	w.WriteHeader(status)
	if r != nil && r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(b)
}

func cloneRequestHeaders(src http.Header) http.Header {
	out := make(http.Header)
	if src == nil {
		return out
	}
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

func copyResponseHeaders(dst http.Header, src http.Header) {
	if dst == nil || src == nil {
		return
	}
	for k, vals := range src {
		lk := strings.ToLower(k)
		if isHopByHopHeader(lk) {
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

func defaultInt(v int, fallback int) int {
	if v <= 0 {
		return fallback
	}
	return v
}

func defaultAPIClient(custom *http.Client) *http.Client {
	if custom != nil {
		return custom
	}
	tr := defaultTransport()
	return &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second,
	}
}

func defaultDownloadClient(custom *http.Client) *http.Client {
	if custom != nil {
		return custom
	}
	tr := defaultTransport()
	return &http.Client{
		Transport: tr,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func defaultTransport() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   64,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 0,
	}
}
