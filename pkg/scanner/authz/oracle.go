package authz

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/gqls-cli/gqls/pkg/transport"
)

// Class is a coarse classification of a GraphQL HTTP response, used as the
// single shared taxonomy for every authorization decision. Checks express
// findings as "two responses classify differently" rather than maintaining
// their own ad-hoc regex tables.
type Class int

const (
	// ClassUnknown is the conservative default: the response could not be
	// classified definitively and must never drive a finding.
	ClassUnknown Class = iota
	// ClassSuccess is HTTP 200 with a non-null `data` object and no errors.
	ClassSuccess
	// ClassAuthDenied is an authentication/authorization rejection (401/403 or
	// an auth-coded/worded GraphQL error).
	ClassAuthDenied
	// ClassValidation is a GraphQL schema/input validation error — the request
	// reached the resolver layer past any auth middleware.
	ClassValidation
	// ClassNotFound is a "no such object" outcome (object null / not-found message).
	ClassNotFound
	// ClassRateLimited is a throttling/rate-limit rejection (429 or worded).
	ClassRateLimited
	// ClassServerError is a 5xx or internal server error.
	ClassServerError
	// ClassEmpty is HTTP 200 with `data` present but null and no errors.
	ClassEmpty
)

// String returns a stable lowercase name for the class.
func (c Class) String() string {
	switch c {
	case ClassSuccess:
		return "success"
	case ClassAuthDenied:
		return "auth_denied"
	case ClassValidation:
		return "validation"
	case ClassNotFound:
		return "not_found"
	case ClassRateLimited:
		return "rate_limited"
	case ClassServerError:
		return "server_error"
	case ClassEmpty:
		return "empty"
	default:
		return "unknown"
	}
}

// authMsgRe matches GraphQL error messages that signal an auth denial.
var authMsgRe = regexp.MustCompile(`(?i)\b(unauthorized|unauthenticated|not authorized|forbidden|access denied|permission denied|must be (logged in|authenticated)|requires? (authentication|login|authorization))\b`)

// authCodes is the set of extensions.code values that unambiguously denote auth denial.
var authCodes = map[string]bool{
	"UNAUTHENTICATED":   true,
	"UNAUTHORIZED":      true,
	"FORBIDDEN":         true,
	"ACCESS_DENIED":     true,
	"PERMISSION_DENIED": true,
}

// rateMsgRe matches throttling / rate-limit error messages.
var rateMsgRe = regexp.MustCompile(`(?i)(rate.?limit|too many requests|throttl|slow down|try again later)`)

// validationMsgRe matches GraphQL schema/input validation errors, indicating the
// request was processed past the authentication layer. Mirrors the patterns
// previously duplicated in gql011/gql012.
var validationMsgRe = regexp.MustCompile(`(?i)(argument .{1,80} of type .{1,80} is required|\bfield .{1,80} is required\b|missing required arguments?|expected type .{1,60}, found|got invalid value|unknown argument|cannot query field|is not defined on type|must not have a selection since type)`)

// validationCodes is the set of extensions.code values denoting validation errors.
var validationCodes = map[string]bool{
	"GRAPHQL_VALIDATION_FAILED": true,
	"missingRequiredArguments":  true,
	"argumentNotProvided":       true,
	"BAD_USER_INPUT":            true,
}

// notFoundMsgRe matches "object not found" error messages.
var notFoundMsgRe = regexp.MustCompile(`(?i)(not found|does not exist|no such|could not find|unknown (id|record))`)

// gqlEnvelope is the minimal GraphQL response shape used for classification.
type gqlEnvelope struct {
	Data   json.RawMessage `json:"data"`
	Errors []struct {
		Message    string `json:"message"`
		Extensions struct {
			Code string `json:"code"`
		} `json:"extensions"`
	} `json:"errors"`
}

// Classify maps an HTTP response to a single Class. It is conservative: only
// definitive signals produce an actionable class; everything else is
// ClassUnknown so that ambiguous responses never drive a finding.
func Classify(resp *transport.Response) Class {
	if resp == nil {
		return ClassUnknown
	}

	// Transport-level status codes take priority over body content.
	switch {
	case resp.StatusCode == 401 || resp.StatusCode == 403:
		return ClassAuthDenied
	case resp.StatusCode == 429:
		return ClassRateLimited
	case resp.StatusCode >= 500:
		return ClassServerError
	}

	var env gqlEnvelope
	if err := json.Unmarshal(resp.Body, &env); err != nil {
		return ClassUnknown
	}

	// Error-message and error-code signals (auth takes priority over everything,
	// so a partial-data + auth-error response is treated as denied, never a leak).
	for _, e := range env.Errors {
		if authCodes[e.Extensions.Code] || authMsgRe.MatchString(e.Message) {
			return ClassAuthDenied
		}
	}
	for _, e := range env.Errors {
		if rateMsgRe.MatchString(e.Message) {
			return ClassRateLimited
		}
	}
	for _, e := range env.Errors {
		if validationCodes[e.Extensions.Code] || validationMsgRe.MatchString(e.Message) {
			return ClassValidation
		}
	}
	for _, e := range env.Errors {
		if notFoundMsgRe.MatchString(e.Message) {
			return ClassNotFound
		}
	}

	// No actionable errors — decide on the data envelope.
	hasData := env.Data != nil && strings.TrimSpace(string(env.Data)) != "null"
	if resp.StatusCode == 200 && hasData && len(env.Errors) == 0 {
		return ClassSuccess
	}
	if resp.StatusCode == 200 && env.Data != nil && strings.TrimSpace(string(env.Data)) == "null" && len(env.Errors) == 0 {
		return ClassEmpty
	}

	return ClassUnknown
}

// Diff describes how an owner (higher-privilege) and an attacker
// (lower-privilege) response compare for an authorization decision.
type Diff struct {
	// SameObject is true when the attacker successfully received the *owner's*
	// object — i.e. the stable identifier extracted from the attacker response
	// equals the owner's. This is the BOLA / cross-tenant positive signal.
	SameObject bool
	// OwnerClass is the classification of the owner/higher-privilege response.
	OwnerClass Class
	// AttackerClass is the classification of the attacker/lower-privilege response.
	AttackerClass Class
	// LeakedFields lists the top-level scalar field names the attacker received
	// under the queried object (best-effort, for evidence).
	LeakedFields []string
}

// Compare evaluates an owner vs attacker response pair for an object access.
// idPath is a dotted path to the object's identifier (e.g. "data.user.id");
// when it cannot be resolved, Compare falls back to the first id-like scalar
// leaf found anywhere in the response.
//
// SameObject is set only when the attacker response classifies as ClassSuccess
// and a non-empty identifier was found that equals the owner's identifier.
func Compare(owner, attacker *transport.Response, idPath string) Diff {
	d := Diff{
		OwnerClass:    Classify(owner),
		AttackerClass: Classify(attacker),
	}

	ownerID := extractID(owner, idPath)
	attackerID := extractID(attacker, idPath)

	if d.AttackerClass == ClassSuccess && ownerID != "" && ownerID == attackerID {
		d.SameObject = true
	}
	d.LeakedFields = leafFields(attacker, idPath)
	return d
}

// objectRoot returns the object node selected by idPath's leading "data.<root>"
// portion, plus the leaf key (e.g. "id") that idPath targets.
func dataRoot(resp *transport.Response, idPath string) (map[string]interface{}, string) {
	if resp == nil {
		return nil, ""
	}
	var top map[string]interface{}
	if err := json.Unmarshal(resp.Body, &top); err != nil {
		return nil, ""
	}
	segs := strings.Split(idPath, ".")
	leaf := ""
	if len(segs) > 0 {
		leaf = segs[len(segs)-1]
		segs = segs[:len(segs)-1]
	}
	cur := interface{}(top)
	for _, s := range segs {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return nil, leaf
		}
		cur = m[s]
	}
	if m, ok := cur.(map[string]interface{}); ok {
		return m, leaf
	}
	return nil, leaf
}

// extractID resolves the object identifier for a response. It first tries the
// exact idPath; failing that it searches for the first id-like scalar leaf
// anywhere in the response body.
func extractID(resp *transport.Response, idPath string) string {
	obj, leaf := dataRoot(resp, idPath)
	if obj != nil && leaf != "" {
		if v, ok := obj[leaf]; ok {
			if s := scalarString(v); s != "" {
				return s
			}
		}
	}
	// Fallback: any id-like scalar leaf in the whole body.
	if resp == nil {
		return ""
	}
	var top interface{}
	if err := json.Unmarshal(resp.Body, &top); err != nil {
		return ""
	}
	return findIDLeaf(top)
}

// FirstID returns the first identifier-like scalar value found anywhere in the
// response body, or "" when none is present. It is used to discover an object id
// (e.g. from a viewer/list query) to drive object-level authorization tests.
func FirstID(resp *transport.Response) string {
	if resp == nil {
		return ""
	}
	var top interface{}
	if err := json.Unmarshal(resp.Body, &top); err != nil {
		return ""
	}
	return findIDLeaf(top)
}

// idLeafRe matches identifier-like JSON keys.
var idLeafRe = regexp.MustCompile(`(?i)^(id|_id|.*Id|nodeId|uuid|guid)$`)

// findIDLeaf walks v depth-first and returns the first id-like scalar value.
func findIDLeaf(v interface{}) string {
	switch t := v.(type) {
	case map[string]interface{}:
		// Deterministic key order.
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		strSort(keys)
		for _, k := range keys {
			if idLeafRe.MatchString(k) {
				if s := scalarString(t[k]); s != "" {
					return s
				}
			}
		}
		for _, k := range keys {
			if s := findIDLeaf(t[k]); s != "" {
				return s
			}
		}
	case []interface{}:
		for _, e := range t {
			if s := findIDLeaf(e); s != "" {
				return s
			}
		}
	}
	return ""
}

// leafFields returns the top-level scalar field names present under the object
// targeted by idPath (best-effort, sorted), for evidence in findings.
func leafFields(resp *transport.Response, idPath string) []string {
	obj, _ := dataRoot(resp, idPath)
	if obj == nil {
		return nil
	}
	var out []string
	for k, v := range obj {
		if scalarString(v) != "" {
			out = append(out, k)
		}
	}
	strSort(out)
	return out
}

// scalarString renders a JSON scalar (string/number/bool) as a string; returns
// "" for objects, arrays, and null.
func scalarString(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		return fmt.Sprintf("%v", t)
	case float64:
		// Render integers without a trailing ".0".
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%g", t)
	default:
		return ""
	}
}

// strSort sorts a string slice in place (small helper to avoid importing sort
// twice with different aliases).
func strSort(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
