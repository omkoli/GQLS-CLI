package schema

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gqls-cli/gqls/pkg/transport"
)

// pathIndexOf returns the position of path in commonGraphQLPaths, or -1.
func pathIndexOf(path string) int {
	for i, p := range commonGraphQLPaths {
		if p == path {
			return i
		}
	}
	return -1
}

// commonGraphQLPaths is the ordered list of well-known GraphQL endpoint paths to probe.
var commonGraphQLPaths = []string{
	"/graphql",
	"/api/graphql",
	"/v1/graphql",
	"/v2/graphql",
	"/gql",
	"/query",
	"/graph",
	"/api/v1/graphql",
	"/api/v2/graphql",
	"/graphql/v1",
	"/graphql/v2",
	"/api",
	"/graphql/query",
}

// discoveryProbeTimeout is the short timeout used for each discovery probe.
const discoveryProbeTimeout = 3 * time.Second

// discoverEndpoint probes all well-known GraphQL paths concurrently and returns the
// valid endpoint whose path appears earliest in commonGraphQLPaths.
// When multiple paths respond as valid GraphQL endpoints, the one with the lowest index
// wins deterministically — regardless of which goroutine finishes first.
// Returns ("", false) if no path responds correctly.
func discoverEndpoint(ctx context.Context, baseURL string, client *transport.Client) (string, bool) {
	baseURL = strings.TrimRight(baseURL, "/")

	// Use a short-timeout client for discovery probes.
	probeClient := transport.NewClient(discoveryProbeTimeout, 20, nil)

	type result struct {
		idx int
		url string
	}

	// Buffered so goroutines never block on send.
	results := make(chan result, len(commonGraphQLPaths))
	var wg sync.WaitGroup

	for i, path := range commonGraphQLPaths {
		wg.Add(1)
		go func(idx int, p string) {
			defer wg.Done()
			fullURL := baseURL + p
			if isGraphQLEndpoint(ctx, probeClient, fullURL) {
				results <- result{idx: idx, url: fullURL}
			}
		}(i, path)
	}

	// Wait for all probes, then close so we can range over results.
	wg.Wait()
	close(results)

	// Pick the successful result with the lowest index in commonGraphQLPaths.
	best := result{idx: len(commonGraphQLPaths)}
	found := false
	for r := range results {
		if r.idx < best.idx {
			best = r
			found = true
		}
	}

	if found {
		return best.url, true
	}
	return "", false
}

// isGraphQLEndpoint sends a minimal GraphQL query to the URL and returns true if it
// receives a valid GraphQL response (status 200 AND body contains "__typename" or "data" key).
func isGraphQLEndpoint(ctx context.Context, client *transport.Client, targetURL string) bool {
	body := `{"query":"{ __typename }"}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewBufferString(body))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}

	if resp.StatusCode != http.StatusOK {
		return false
	}

	bodyStr := string(resp.Body)
	if strings.Contains(bodyStr, `"__typename"`) {
		return true
	}

	// Also accept any valid JSON with a "data" key.
	var check map[string]json.RawMessage
	if err := json.Unmarshal(resp.Body, &check); err != nil {
		return false
	}
	_, hasData := check["data"]
	return hasData
}
