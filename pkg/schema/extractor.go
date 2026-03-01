package schema

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gqls-cli/gqls/pkg/transport"
)

// FullIntrospectionQuery is the standard GraphQL introspection query sent to discover schema.
const FullIntrospectionQuery = `query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args { ...InputValue }
    }
  }
}
fragment FullType on __Type {
  kind name description
  fields(includeDeprecated: true) {
    name description
    args { ...InputValue }
    type { ...TypeRef }
    isDeprecated deprecationReason
  }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason }
  possibleTypes { ...TypeRef }
}
fragment InputValue on __InputValue {
  name description
  type { ...TypeRef }
  defaultValue
}
fragment TypeRef on __Type {
  kind name
  ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } }
}`

// ExtractionResult holds the schema and any non-fatal errors from the extraction pipeline.
type ExtractionResult struct {
	Schema *Schema
	Errors []ExtractionError
}

// ExtractionError records a failure at a specific pipeline stage.
type ExtractionError struct {
	Stage   string
	Message string
	Fatal   bool
}

// Extractor orchestrates the full schema extraction pipeline.
type Extractor struct {
	client  *transport.Client
	timeout time.Duration
}

// NewExtractor creates a new Extractor with the given client and per-request timeout.
// Pass 0 to use the default 30-second timeout.
func NewExtractor(client *transport.Client, timeout time.Duration) *Extractor {
	return &Extractor{
		client:  client,
		timeout: timeout,
	}
}

// Extract runs the full extraction pipeline against rawURL and returns the result.
func (e *Extractor) Extract(ctx context.Context, rawURL string) (*ExtractionResult, error) {
	result := &ExtractionResult{}

	// Stage 1: URL normalization.
	endpoint, err := normalizeURL(rawURL)
	if err != nil {
		return nil, fmt.Errorf("url normalization: %w", err)
	}

	// Stage 2: Endpoint discovery — if path is empty or just "/".
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("url parse: %w", err)
	}
	if parsed.Path == "" || parsed.Path == "/" {
		discovered, ok := discoverEndpoint(ctx, endpoint, e.client)
		if ok {
			endpoint = discovered
			if s, err2 := url.Parse(discovered); err2 == nil {
				// We'll record the path in metadata after schema is built.
				_ = s
			}
		}
	}

	// Stage 3: Auth probe — send { __typename } without extra headers.
	authRequired, authErr := e.probeAuth(ctx, endpoint)
	if authErr != nil {
		result.Errors = append(result.Errors, ExtractionError{
			Stage:   "auth_probe",
			Message: authErr.Error(),
			Fatal:   true,
		})
		return result, nil
	}

	// Stage 4: Full introspection.
	raw, probeCount, introspectionErr := e.sendIntrospection(ctx, endpoint, FullIntrospectionQuery)
	probeCount++ // count the full introspection attempt

	// Stage 5: Check if full introspection succeeded.
	if introspectionErr == nil && raw != nil {
		schema, normalizeErr := Normalize(raw)
		if normalizeErr == nil {
			schema.Endpoint = endpoint
			schema.Metadata.IntrospectionEnabled = true
			schema.Metadata.AuthRequired = authRequired
			schema.Metadata.ProbeCount = probeCount
			schema.Metadata.RawResponseSize = len(raw)

			// Check if endpoint was discovered.
			if parsed.Path == "" || parsed.Path == "/" {
				if ep, err2 := url.Parse(endpoint); err2 == nil && ep.Path != "" && ep.Path != "/" {
					schema.Metadata.EndpointDiscovered = true
					schema.Metadata.DiscoveredPath = ep.Path
				}
			}

			result.Schema = schema
			return result, nil
		}
		// Normalization error is non-fatal; fall through to try partial introspection.
		result.Errors = append(result.Errors, ExtractionError{
			Stage:   "normalize",
			Message: normalizeErr.Error(),
			Fatal:   false,
		})
	}

	// Stage 6: Minimal introspection check.
	minimalQuery := `{ __schema { queryType { name } } }`
	minRaw, minCount, minErr := e.sendIntrospection(ctx, endpoint, minimalQuery)
	probeCount += minCount + 1

	hasPartial := minErr == nil && minRaw != nil && hasSchemaData(minRaw)
	if hasPartial {
		result.Errors = append(result.Errors, ExtractionError{
			Stage:   "partial_introspection",
			Message: "server supports partial introspection only; falling back to field suggestion harvesting",
			Fatal:   false,
		})
	}

	// Stage 7: Field suggestion harvesting.
	harvester := NewHarvester(e.client, endpoint)
	harvestedSchema, harvestErr := harvester.Harvest(ctx)
	if harvestErr != nil {
		result.Errors = append(result.Errors, ExtractionError{
			Stage:   "harvesting",
			Message: harvestErr.Error(),
			Fatal:   false,
		})
	}

	if harvestedSchema != nil {
		harvestedSchema.Endpoint = endpoint
		harvestedSchema.Metadata.AuthRequired = authRequired
		harvestedSchema.Metadata.ProbeCount = probeCount + harvester.probeCount
		result.Schema = harvestedSchema

		if parsed.Path == "" || parsed.Path == "/" {
			if ep, err2 := url.Parse(endpoint); err2 == nil && ep.Path != "" && ep.Path != "/" {
				harvestedSchema.Metadata.EndpointDiscovered = true
				harvestedSchema.Metadata.DiscoveredPath = ep.Path
			}
		}
		return result, nil
	}

	// If we got partial introspection data, return a partial schema.
	if hasPartial {
		partialSchema := &Schema{
			Endpoint:         endpoint,
			ExtractedAt:      time.Now(),
			ExtractionMethod: MethodPartial,
			Types:            make(map[string]*TypeDef),
			Metadata: ExtractionMetadata{
				IntrospectionEnabled: false,
				AuthRequired:         authRequired,
				ProbeCount:           probeCount,
				RawResponseSize:      len(minRaw),
			},
		}
		result.Schema = partialSchema
		return result, nil
	}

	// If nothing worked, return what we have (may be nil schema).
	result.Errors = append(result.Errors, ExtractionError{
		Stage:   "extraction",
		Message: "could not extract schema via introspection or field suggestions",
		Fatal:   false,
	})
	return result, nil
}

// probeAuth sends { __typename } and checks if auth is required.
// Returns (authRequired, error). error is non-nil only if auth is required AND configured headers don't fix it.
func (e *Extractor) probeAuth(ctx context.Context, endpoint string) (bool, error) {
	body := `{"query":"{ __typename }"}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("creating auth probe request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Del("Accept-Encoding")
	req.Header.Set("Accept-Encoding", "identity")

	// Send without configured auth headers (use a bare client just for the probe).
	bareClient := transport.NewClient(e.clientTimeout(), 10, nil)
	resp, err := bareClient.Do(req)
	if err != nil {
		// Network error — assume no auth issue, let the real requests fail.
		return false, nil
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		// Auth is required — try with configured headers.
		req2, err2 := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
		if err2 != nil {
			return true, fmt.Errorf("creating authenticated probe: %w", err2)
		}
		req2.Header.Set("Content-Type", "application/json")

		resp2, err2 := e.client.Do(req2)
		if err2 != nil {
			return true, fmt.Errorf("authenticated probe failed: %w", err2)
		}
		if resp2.StatusCode == http.StatusUnauthorized || resp2.StatusCode == http.StatusForbidden {
			return true, fmt.Errorf("authentication failed: server returned %d even with configured headers", resp2.StatusCode)
		}
		return true, nil
	}

	return false, nil
}

// sendIntrospection sends a GraphQL query and returns the raw response body.
func (e *Extractor) sendIntrospection(ctx context.Context, endpoint, query string) (json.RawMessage, int, error) {
	payload := map[string]string{"query": query}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Del("Accept-Encoding")
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, 1, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, 1, fmt.Errorf("introspection returned status %d", resp.StatusCode)
	}

	// Check if we have __schema data.
	var check struct {
		Data struct {
			Schema *json.RawMessage `json:"__schema"`
		} `json:"data"`
		Errors []json.RawMessage `json:"errors"`
	}
	if err := json.Unmarshal(resp.Body, &check); err != nil {
		return nil, 1, fmt.Errorf("unmarshal introspection check: %w", err)
	}

	if check.Data.Schema == nil {
		if len(check.Errors) > 0 {
			return nil, 1, fmt.Errorf("introspection returned errors")
		}
		return nil, 1, fmt.Errorf("introspection returned no schema data")
	}

	return json.RawMessage(resp.Body), 1, nil
}

// hasSchemaData returns true if the raw response contains non-null __schema.data.
func hasSchemaData(raw json.RawMessage) bool {
	var check struct {
		Data struct {
			Schema *json.RawMessage `json:"__schema"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &check); err != nil {
		return false
	}
	return check.Data.Schema != nil
}

// normalizeURL ensures the URL has an http or https scheme (defaulting to https) and
// strips trailing slashes. Returns an error for unsupported schemes such as ftp://, file://.
func normalizeURL(rawURL string) (string, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", fmt.Errorf("empty URL")
	}

	// Add scheme if missing.
	if !strings.Contains(rawURL, "://") {
		rawURL = "https://" + rawURL
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	// Enforce http or https only.
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("unsupported URL scheme %q: only http and https are allowed", parsed.Scheme)
	}

	// Strip trailing slash from path (but keep "/" if there's no path component).
	if len(parsed.Path) > 1 {
		parsed.Path = strings.TrimRight(parsed.Path, "/")
	}

	return parsed.String(), nil
}

// clientTimeout returns the configured timeout or a 30s default.
func (e *Extractor) clientTimeout() time.Duration {
	if e.timeout > 0 {
		return e.timeout
	}
	return 30 * time.Second
}
