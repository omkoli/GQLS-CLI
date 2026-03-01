package schema

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gqls-cli/gqls/pkg/transport"
)

// seedProbes is the list of root-level field names to probe via typo injection.
var seedProbes = []string{
	"user", "users", "me", "account", "profile", "viewer", "currentUser",
	"admin", "settings", "config",
	"order", "orders", "product", "products", "item", "items",
	"payment", "transaction", "invoice",
	"post", "posts", "article", "articles", "comment", "comments",
	"health", "status", "version",
	"organization", "team", "member", "role",
	"file", "upload", "media", "image",
	"notification", "event", "log",
	"search", "query", "report",
}

// graphqlIdentifierRE matches a valid GraphQL identifier: [A-Za-z_][A-Za-z0-9_]*
var graphqlIdentifierRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// isValidGraphQLIdentifier returns true if s is a valid GraphQL field/type identifier.
func isValidGraphQLIdentifier(s string) bool {
	return graphqlIdentifierRE.MatchString(s)
}

// suggestionPatterns is the set of regexes used to extract field names from error messages.
var suggestionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`Did you mean "([^"]+)"\?`),
	regexp.MustCompile(`Did you mean '([^']+)'\?`),
	regexp.MustCompile(`did you mean "([^"]+)"`),
	regexp.MustCompile(`Suggestions: \[([^\]]+)\]`),
	regexp.MustCompile(`Perhaps you meant: ([a-zA-Z_][a-zA-Z0-9_]*)`),
}

// Harvester extracts schema information from an introspection-disabled endpoint
// by exploiting GraphQL field suggestion error messages.
type Harvester struct {
	client     *transport.Client
	targetURL  string
	maxDepth   int
	probeCount int

	mu        sync.Mutex
	discovered map[string]map[string]bool // type -> set of field names
}

// NewHarvester creates a new Harvester with a default maxDepth of 3.
func NewHarvester(client *transport.Client, targetURL string) *Harvester {
	return &Harvester{
		client:     client,
		targetURL:  targetURL,
		maxDepth:   3,
		discovered: make(map[string]map[string]bool),
	}
}

// Harvest runs the field suggestion harvesting strategy and returns a partial Schema.
func (h *Harvester) Harvest(ctx context.Context) (*Schema, error) {
	// Probe seed fields concurrently with a max of 5 goroutines.
	sem := make(chan struct{}, 5)
	var wg sync.WaitGroup

	for _, seed := range seedProbes {
		select {
		case <-ctx.Done():
			break
		default:
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(s string) {
			defer wg.Done()
			defer func() { <-sem }()

			// Try typos of the seed to get suggestions.
			typos := generateTypos(s)
			for _, typo := range typos {
				fields := h.probeTopLevel(ctx, typo)
				for _, f := range fields {
					h.markDiscovered("Query", f)
					// Recursively probe sub-fields up to maxDepth.
					h.harvestSubFields(ctx, f, 1)
				}
			}
		}(seed)
	}

	wg.Wait()

	return h.buildSchema(), nil
}

// probeTopLevel sends a typo query at the top level and extracts suggested field names.
func (h *Harvester) probeTopLevel(ctx context.Context, typo string) []string {
	query := fmt.Sprintf(`{ %s { id } }`, typo)
	raw := h.sendQuery(ctx, query)
	h.mu.Lock()
	h.probeCount++
	h.mu.Unlock()
	return extractSuggestions(raw)
}

// harvestSubFields recursively probes sub-fields of a known field.
func (h *Harvester) harvestSubFields(ctx context.Context, parentField string, depth int) {
	if depth >= h.maxDepth {
		return
	}

	for _, seed := range seedProbes {
		select {
		case <-ctx.Done():
			return
		default:
		}

		typos := generateTypos(seed)
		for _, typo := range typos {
			query := fmt.Sprintf(`{ %s { %s { id } } }`, parentField, typo)
			raw := h.sendQuery(ctx, query)
			h.mu.Lock()
			h.probeCount++
			h.mu.Unlock()

			suggestions := extractSuggestions(raw)
			for _, sub := range suggestions {
				// Record sub-field under parentField as the type key.
				// checkAndMarkDiscovered is atomic: it checks and sets under one lock,
				// preventing the TOCTOU race that existed with separate isDiscovered/markDiscovered calls.
				if h.checkAndMarkDiscovered(parentField, sub) {
					h.harvestSubFields(ctx, sub, depth+1)
				}
			}
		}
	}
}

// sendQuery sends a raw GraphQL query string and returns the response body.
func (h *Harvester) sendQuery(ctx context.Context, query string) []byte {
	payload := map[string]string{"query": query}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.targetURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		return nil
	}
	return resp.Body
}

// extractSuggestions parses a GraphQL error response and returns all suggested field names.
// Each returned name is a validated GraphQL identifier ([A-Za-z_][A-Za-z0-9_]*).
// Suggestion text from the server is treated as untrusted: names that are not valid
// identifiers are silently dropped to prevent query injection.
func extractSuggestions(body []byte) []string {
	if len(body) == 0 {
		return nil
	}

	var resp struct {
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil
	}

	seen := make(map[string]bool)
	var results []string

	addIfValid := func(raw string) {
		// Strip optional surrounding single or double quotes (e.g. from list items).
		raw = strings.TrimSpace(raw)
		raw = strings.Trim(raw, `"'`)
		raw = strings.TrimSpace(raw)
		if isValidGraphQLIdentifier(raw) && !seen[raw] {
			seen[raw] = true
			results = append(results, raw)
		}
	}

	for _, e := range resp.Errors {
		for _, pat := range suggestionPatterns {
			matches := pat.FindStringSubmatch(e.Message)
			if len(matches) < 2 {
				continue
			}
			captured := matches[1]
			// Split on commas to handle list-style suggestions such as
			// "Suggestions: [user, users, viewer]" which capture the whole list.
			// For single-name patterns this produces a one-element slice.
			for _, part := range strings.Split(captured, ",") {
				addIfValid(part)
			}
		}
	}
	return results
}

// generateTypos returns a set of typos for the given word to trigger suggestion errors.
func generateTypos(word string) []string {
	if len(word) < 2 {
		return []string{word + "z"}
	}
	typos := make([]string, 0, 3)
	typos = append(typos, word+"z")
	typos = append(typos, "x"+word)
	// Swap first two characters.
	runes := []rune(word)
	runes[0], runes[1] = runes[1], runes[0]
	typos = append(typos, string(runes))
	return typos
}

// markDiscovered records a field name under the given type key.
func (h *Harvester) markDiscovered(typeKey, fieldName string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.discovered[typeKey] == nil {
		h.discovered[typeKey] = make(map[string]bool)
	}
	h.discovered[typeKey][fieldName] = true
}

// checkAndMarkDiscovered atomically checks whether fieldName under typeKey has been seen
// and, if not, records it. Returns true if the field was newly added, false if already
// present. Using a single lock for both operations eliminates the TOCTOU window that
// existed when isDiscovered and markDiscovered were called separately.
func (h *Harvester) checkAndMarkDiscovered(typeKey, fieldName string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.discovered[typeKey] == nil {
		h.discovered[typeKey] = make(map[string]bool)
	}
	if h.discovered[typeKey][fieldName] {
		return false // already seen
	}
	h.discovered[typeKey][fieldName] = true
	return true // newly added
}

// buildSchema constructs a partial Schema from the discovered field map.
func (h *Harvester) buildSchema() *Schema {
	h.mu.Lock()
	defer h.mu.Unlock()

	s := &Schema{
		ExtractedAt:      time.Now(),
		ExtractionMethod: MethodFieldSuggestion,
		Types:            make(map[string]*TypeDef),
		Metadata: ExtractionMetadata{
			SuggestionsEnabled: true,
			ProbeCount:         h.probeCount,
		},
	}

	for typeName, fields := range h.discovered {
		td := &TypeDef{
			Name: typeName,
			Kind: KindObject,
		}
		for fieldName := range fields {
			fd := &FieldDef{Name: fieldName}
			ClassifyField(fd)
			td.Fields = append(td.Fields, fd)
		}
		ClassifyType(td)
		s.Types[typeName] = td
	}

	// Wire up QueryType if we have Query fields.
	if qt, ok := s.Types["Query"]; ok {
		s.QueryType = qt
	}

	return s
}
