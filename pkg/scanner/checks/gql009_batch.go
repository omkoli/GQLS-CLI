package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

const defaultBatchSize = 100

type batchAbuseCheck struct {
	batchSize int
}

func init() {
	MustRegister(&batchAbuseCheck{batchSize: defaultBatchSize})
}

func (c *batchAbuseCheck) ID() string           { return "GQL-009" }
func (c *batchAbuseCheck) Name() string         { return "Batch Query Abuse" }
func (c *batchAbuseCheck) Category() Category   { return DenialOfService }
func (c *batchAbuseCheck) Severity() Severity   { return HIGH }
func (c *batchAbuseCheck) RequiresSchema() bool { return false }

type batchOperation struct {
	Query string `json:"query"`
}

func (c *batchAbuseCheck) Run(ctx context.Context, cc *CheckContext) (CheckResult, error) {
	result := CheckResult{CheckID: c.ID(), Ran: true}

	batchSize := c.batchSize
	if batchSize <= 0 {
		batchSize = defaultBatchSize
	}

	ops := make([]batchOperation, batchSize)
	for i := range ops {
		ops[i] = batchOperation{Query: "{ __typename }"}
	}

	payload, err := json.Marshal(ops)
	if err != nil {
		result.Error = fmt.Errorf("marshalling batch payload: %w", err)
		return result, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cc.Target, bytes.NewReader(payload))
	if err != nil {
		result.Error = fmt.Errorf("constructing batch request: %w", err)
		return result, nil
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := cc.ProbeClient().Do(req)
	result.ProbeCount++
	if err != nil {
		result.Error = fmt.Errorf("sending batch request: %w", err)
		return result, nil
	}

	var responses []json.RawMessage
	if jsonErr := json.Unmarshal(resp.Body, &responses); jsonErr != nil {
		result.PassReason = "server does not support GraphQL batching (response is not a JSON array)"
		result.PassProbes = []PassProbe{{
			Label:   fmt.Sprintf("batch-probe (%d ops)", batchSize),
			Request: resp.Request,
			Body:    payload,
		}}
		return result, nil
	}

	if len(responses) < batchSize {
		result.PassReason = fmt.Sprintf(
			"server returned only %d/%d responses; batch size limit appears to be enforced",
			len(responses), batchSize,
		)
		result.PassProbes = []PassProbe{{
			Label:   fmt.Sprintf("batch-probe (%d ops, %d returned)", batchSize, len(responses)),
			Request: resp.Request,
			Body:    payload,
		}}
		return result, nil
	}

	allSuccess := true
	for _, raw := range responses {
		var entry struct {
			Data   json.RawMessage   `json:"data"`
			Errors []json.RawMessage `json:"errors"`
		}
		if json.Unmarshal(raw, &entry) != nil {
			allSuccess = false
			break
		}
		if entry.Data == nil {
			allSuccess = false
			break
		}
		if len(entry.Errors) > 0 {
			allSuccess = false
			break
		}
	}

	if !allSuccess {
		result.PassReason = "one or more batch operations returned errors; batch abuse not confirmed"
		result.PassProbes = []PassProbe{{
			Label:   fmt.Sprintf("batch-probe (%d ops)", batchSize),
			Request: resp.Request,
			Body:    payload,
		}}
		return result, nil
	}

	result.Findings = append(result.Findings, Finding{
		CheckID:   c.ID(),
		CheckName: c.Name(),
		Severity:  HIGH,
		Category:  DenialOfService,
		Title:     "GraphQL Batch Query Abuse Allowed",
		Description: fmt.Sprintf(
			"The endpoint accepted and successfully executed a batch of %d identical GraphQL "+
				"operations in a single HTTP request. Every operation returned a successful "+
				"response with no errors, indicating no server-side batch size limit is enforced.",
			batchSize,
		),
		Impact: fmt.Sprintf(
			"An attacker can amplify server load by up to %d× per HTTP request, bypassing "+
				"rate-limiting controls that operate at the HTTP layer. Sustained batched "+
				"requests can exhaust CPU, memory, and downstream resource quotas, causing "+
				"service degradation or denial of service for legitimate users.",
			batchSize,
		),
		Remediation: "Enforce a maximum batch size (recommended ≤ 10 operations per request). " +
			"In Apollo Server set maxOperationCount in ApolloServerPluginBatchHttpRequests. " +
			"In other frameworks, validate the request body and reject arrays larger than the " +
			"configured threshold before query execution. Apply rate limiting at the operation " +
			"level rather than only at the HTTP request level.",
		References: []string{
			"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html#batching-attacks",
			"https://www.apollographql.com/docs/apollo-server/security/cors/#http-batching",
		},
		ReproRequest: resp.Request,
		ReproBody:    payload,
		Fingerprint:  GenerateFingerprint(c.ID(), cc.Target, "batch_abuse"),
	})

	return result, nil
}
