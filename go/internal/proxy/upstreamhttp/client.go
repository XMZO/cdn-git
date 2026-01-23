package upstreamhttp

import (
	"net/http"
	"time"
)

type Options struct {
	// Timeout is the overall request timeout (includes body). Leave 0 to disable.
	Timeout time.Duration

	// FollowRedirects controls whether redirects are followed. If false, 3xx is returned to caller.
	FollowRedirects bool
}

func NewClient(opts Options) *http.Client {
	base, _ := http.DefaultTransport.(*http.Transport)
	tr := base.Clone()

	// Improve connection reuse under concurrency (default MaxIdleConnsPerHost is 2).
	tr.MaxIdleConns = 256
	tr.MaxIdleConnsPerHost = 64
	tr.ForceAttemptHTTP2 = true

	c := &http.Client{
		Transport: tr,
		Timeout:   opts.Timeout,
	}
	if !opts.FollowRedirects {
		c.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return c
}
