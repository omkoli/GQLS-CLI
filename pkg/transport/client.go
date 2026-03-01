// Package transport provides a rate-limited, header-injecting HTTP client for the scanner.
package transport

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

// Response wraps an HTTP response with the captured body, latency, and originating request.
type Response struct {
	// StatusCode is the HTTP response status code.
	StatusCode int
	// Headers contains the HTTP response headers.
	Headers http.Header
	// Body is the complete, fully-buffered response body.
	Body []byte
	// Latency is the round-trip duration from sending the request to reading the last byte.
	Latency time.Duration
	// Request is the originating *http.Request, with its body reset for re-reading.
	Request *http.Request
}

// Client is a rate-limited HTTP client with default header injection.
type Client struct {
	http        *http.Client
	headers     map[string]string
	rateLimiter *rate.Limiter
}

// NewClient creates a Client with the given per-request timeout, requests-per-second cap,
// and default headers. If rps ≤ 0 it defaults to 10.
func NewClient(timeout time.Duration, rps int, headers map[string]string) *Client {
	if rps <= 0 {
		rps = 10
	}
	lim := rate.NewLimiter(rate.Limit(rps), rps)
	hcopy := make(map[string]string, len(headers))
	for k, v := range headers {
		hcopy[k] = v
	}
	return &Client{
		http:        &http.Client{Timeout: timeout},
		headers:     hcopy,
		rateLimiter: lim,
	}
}

// Do executes req after applying rate limiting and default headers.
// The request body is fully buffered so that it remains readable after the call returns.
// The Authorization header from the client's default headers is always injected,
// overriding any value already set on the request.
func (c *Client) Do(req *http.Request) (*Response, error) {
	// Buffer the request body so callers can re-read it (e.g. for curl generation).
	var bodySnapshot []byte
	if req.Body != nil && req.Body != http.NoBody {
		var err error
		bodySnapshot, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		_ = req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(bodySnapshot))
	}

	// Inject default headers. Authorization always overrides; others fill gaps.
	for k, v := range c.headers {
		if strings.EqualFold(k, "Authorization") {
			req.Header.Set(k, v)
		} else if req.Header.Get(k) == "" {
			req.Header.Set(k, v)
		}
	}

	// Honor the rate limiter — wait blocks until a token is available or ctx is cancelled.
	ctx := req.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	if err := c.rateLimiter.Wait(ctx); err != nil {
		return nil, err
	}

	start := time.Now()
	resp, err := c.http.Do(req)
	latency := time.Since(start)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Reset request body so the caller (e.g. curl generator) can read it again.
	if bodySnapshot != nil {
		req.Body = io.NopCloser(bytes.NewReader(bodySnapshot))
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       respBody,
		Latency:    latency,
		Request:    req,
	}, nil
}
