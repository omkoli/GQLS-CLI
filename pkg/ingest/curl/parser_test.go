package curl_test

import (
	"strings"
	"testing"

	"github.com/gqls-cli/gqls/pkg/ingest/curl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParse_BashPostJSON verifies that a multi-line Bash-style curl command
// (backslash continuations, single-quoted arguments) is parsed correctly.
func TestParse_BashPostJSON(t *testing.T) {
	cmd := "curl -X POST 'https://api.example.com/graphql' \\\n" +
		"  -H 'Content-Type: application/json' \\\n" +
		"  -d '{\"query\":\"{ users { id name } }\"}'"

	pr, err := curl.Parse(cmd)
	require.NoError(t, err)

	assert.Equal(t, "POST", pr.Method)
	assert.Equal(t, "https://api.example.com/graphql", pr.URL)
	assert.Equal(t, "application/json", pr.Headers["Content-Type"])
	assert.Equal(t, `{"query":"{ users { id name } }"}`, pr.Body)
}

// TestParse_CMDPostJSON verifies that a multi-line Windows CMD-style curl
// command (caret continuations, double-quoted arguments, \" escapes) is
// parsed correctly.
func TestParse_CMDPostJSON(t *testing.T) {
	// In CMD the JSON body lives inside double quotes; inner quotes are
	// escaped with \" which the tokeniser resolves to ".
	cmd := "curl -X POST \"https://api.example.com/graphql\" ^\n" +
		"  -H \"Content-Type: application/json\" ^\n" +
		"  -d \"{\\\"query\\\":\\\"{ users { id name } }\\\"}\""

	pr, err := curl.Parse(cmd)
	require.NoError(t, err)

	assert.Equal(t, "POST", pr.Method)
	assert.Equal(t, "https://api.example.com/graphql", pr.URL)
	assert.Equal(t, "application/json", pr.Headers["Content-Type"])
	assert.Equal(t, `{"query":"{ users { id name } }"}`, pr.Body)
}

// TestParse_GETNoBody verifies that a single-line curl command without a body
// or an explicit method defaults to GET.
func TestParse_GETNoBody(t *testing.T) {
	cmd := `curl 'https://api.example.com/graphql'`

	pr, err := curl.Parse(cmd)
	require.NoError(t, err)

	assert.Equal(t, "GET", pr.Method)
	assert.Equal(t, "https://api.example.com/graphql", pr.URL)
	assert.Empty(t, pr.Headers)
	assert.Empty(t, pr.Body)
}

// TestParse_MultipleHeaders verifies that multiple -H flags are all collected
// and that header values containing colons (e.g. Bearer tokens) are preserved.
func TestParse_MultipleHeaders(t *testing.T) {
	cmd := "curl -X POST 'https://api.example.com/graphql' \\\n" +
		"  -H 'Content-Type: application/json' \\\n" +
		"  -H 'Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.tok' \\\n" +
		"  -H 'X-Request-ID: abc-123' \\\n" +
		"  -d '{\"query\":\"{ me { id } }\"}'"

	pr, err := curl.Parse(cmd)
	require.NoError(t, err)

	assert.Equal(t, "POST", pr.Method)
	assert.Equal(t, "https://api.example.com/graphql", pr.URL)
	assert.Equal(t, "application/json", pr.Headers["Content-Type"])
	assert.Equal(t, "Bearer eyJhbGciOiJSUzI1NiJ9.tok", pr.Headers["Authorization"])
	assert.Equal(t, "abc-123", pr.Headers["X-Request-ID"])
	assert.Equal(t, `{"query":"{ me { id } }"}`, pr.Body)
}

// TestParse_EscapedJSONPayload verifies that a CMD-style command whose JSON
// body contains \" escape sequences is decoded to the correct literal JSON,
// and that method is correctly inferred from the presence of a body.
func TestParse_EscapedJSONPayload(t *testing.T) {
	// Raw curl as it would appear in a Windows CMD shell.
	// The -d value is a double-quoted string containing \" to represent
	// literal quote characters inside the JSON.
	cmd := `curl "https://api.example.com/graphql"` +
		` -H "Content-Type: application/json"` +
		` -H "Authorization: Bearer secret-token"` +
		` --data "{\"operationName\":\"GetUser\",\"variables\":{\"id\":\"42\"},\"query\":\"{ user(id: \\\"42\\\") { name email } }\"}"`

	pr, err := curl.Parse(cmd)
	require.NoError(t, err)

	// Method is inferred as POST because a body is present.
	assert.Equal(t, "POST", pr.Method)
	assert.Equal(t, "https://api.example.com/graphql", pr.URL)
	assert.Equal(t, "application/json", pr.Headers["Content-Type"])
	assert.Equal(t, "Bearer secret-token", pr.Headers["Authorization"])

	// \" → ", \\" → \"  (i.e. \\\" in source = \\ then \" = \ then ")
	wantBody := `{"operationName":"GetUser","variables":{"id":"42"},"query":"{ user(id: \"42\") { name email } }"}`
	assert.Equal(t, wantBody, pr.Body)
}

// ---------------------------------------------------------------------------
// Additional edge-case tests
// ---------------------------------------------------------------------------

// TestParse_InferPOSTFromBody verifies that when -X is absent but -d is
// present, the method is inferred as POST.
func TestParse_InferPOSTFromBody(t *testing.T) {
	cmd := `curl https://api.example.com/graphql -d '{"query":"{ __typename }"}'`

	pr, err := curl.Parse(cmd)
	require.NoError(t, err)

	assert.Equal(t, "POST", pr.Method)
	assert.Equal(t, `{"query":"{ __typename }"}`, pr.Body)
}

// TestParse_LongFormFlags verifies --request, --header, and --data-raw.
func TestParse_LongFormFlags(t *testing.T) {
	cmd := "curl --request POST \\\n" +
		"  --header 'Content-Type: application/json' \\\n" +
		"  --data-raw '{\"query\":\"{ __schema { types { name } } }\"}' \\\n" +
		"  'https://api.example.com/graphql'"

	pr, err := curl.Parse(cmd)
	require.NoError(t, err)

	assert.Equal(t, "POST", pr.Method)
	assert.Equal(t, "https://api.example.com/graphql", pr.URL)
	assert.Equal(t, "application/json", pr.Headers["Content-Type"])
	assert.Equal(t, `{"query":"{ __schema { types { name } } }"}`, pr.Body)
}

// TestParse_SkipsUnknownBooleanFlags verifies that boolean flags like -s, -v,
// and -k do not interfere with URL or body extraction.
func TestParse_SkipsUnknownBooleanFlags(t *testing.T) {
	cmd := `curl -s -k -v -X POST https://api.example.com/graphql -H 'Content-Type: application/json' -d '{"query":"{ __typename }"}'`

	pr, err := curl.Parse(cmd)
	require.NoError(t, err)

	assert.Equal(t, "POST", pr.Method)
	assert.Equal(t, "https://api.example.com/graphql", pr.URL)
	assert.Equal(t, "application/json", pr.Headers["Content-Type"])
	assert.Equal(t, `{"query":"{ __typename }"}`, pr.Body)
}

// TestParse_URLFirst verifies that the URL can appear immediately after
// 'curl' before any flags.
func TestParse_URLFirst(t *testing.T) {
	cmd := `curl https://api.example.com/graphql -X GET -H 'Accept: application/json'`

	pr, err := curl.Parse(cmd)
	require.NoError(t, err)

	assert.Equal(t, "GET", pr.Method)
	assert.Equal(t, "https://api.example.com/graphql", pr.URL)
	assert.Equal(t, "application/json", pr.Headers["Accept"])
}

// TestParse_ErrorNoCurl verifies that a command not starting with 'curl'
// returns an appropriate error.
func TestParse_ErrorNoCurl(t *testing.T) {
	_, err := curl.Parse(`wget https://example.com`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "curl")
}

// TestParse_ErrorNoURL verifies that a valid curl command with no URL
// returns an error.
func TestParse_ErrorNoURL(t *testing.T) {
	_, err := curl.Parse(`curl -X POST -H 'Content-Type: application/json'`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "URL")
}

// TestParse_ErrorUnterminatedSingleQuote verifies that an unterminated
// single-quoted string is reported as an error.
func TestParse_ErrorUnterminatedSingleQuote(t *testing.T) {
	_, err := curl.Parse(`curl 'https://example.com`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unterminated")
}

// TestParse_ErrorUnterminatedDoubleQuote verifies that an unterminated
// double-quoted string is reported as an error.
func TestParse_ErrorUnterminatedDoubleQuote(t *testing.T) {
	_, err := curl.Parse(`curl "https://example.com`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unterminated")
}

// ---------------------------------------------------------------------------
// NormalizeCurlInput tests
// ---------------------------------------------------------------------------

// TestNormalizeCurlInput_BashContinuations verifies that Bash-style backslash
// line continuations are collapsed into a single line.
func TestNormalizeCurlInput_BashContinuations(t *testing.T) {
	input := "curl -X POST 'https://api.example.com/graphql' \\\n" +
		"  -H 'Content-Type: application/json' \\\n" +
		"  -d '{\"query\":\"{ __typename }\"}'"

	got, err := curl.NormalizeCurlInput(input)
	require.NoError(t, err)
	assert.NotContains(t, got, "\n", "result must be a single line")
	assert.Contains(t, got, "-H")
	assert.Contains(t, got, "-d")
}

// TestNormalizeCurlInput_CMDContinuations verifies that Windows CMD-style
// caret line continuations are collapsed into a single line.
func TestNormalizeCurlInput_CMDContinuations(t *testing.T) {
	input := "curl -X POST \"https://api.example.com/graphql\" ^\n" +
		"  -H \"Content-Type: application/json\" ^\n" +
		"  -d \"{\\\"query\\\":\\\"{ __typename }\\\"}\""

	got, err := curl.NormalizeCurlInput(input)
	require.NoError(t, err)
	assert.NotContains(t, got, "\n", "result must be a single line")
	assert.Contains(t, got, "-H")
	assert.Contains(t, got, "-d")
}

// TestNormalizeCurlInput_SmartDoubleQuotes verifies that Unicode typographic
// double quotation marks are replaced with ASCII double quotes.
func TestNormalizeCurlInput_SmartDoubleQuotes(t *testing.T) {
	// U+201C and U+201D are the left and right double quotation marks that
	// word processors and messaging apps often substitute for ASCII ".
	input := "curl \u201Chttps://api.example.com/graphql\u201D -X GET"

	got, err := curl.NormalizeCurlInput(input)
	require.NoError(t, err)
	assert.Contains(t, got, `"https://api.example.com/graphql"`,
		"smart double quotes must become ASCII double quotes")
	assert.NotContains(t, got, "\u201C")
	assert.NotContains(t, got, "\u201D")
}

// TestNormalizeCurlInput_SmartSingleQuotes verifies that Unicode typographic
// single quotation marks are replaced with ASCII single quotes.
func TestNormalizeCurlInput_SmartSingleQuotes(t *testing.T) {
	// U+2018 and U+2019 are the left and right single quotation marks.
	input := "curl \u2018https://api.example.com/graphql\u2019 -X GET"

	got, err := curl.NormalizeCurlInput(input)
	require.NoError(t, err)
	assert.Contains(t, got, `'https://api.example.com/graphql'`,
		"smart single quotes must become ASCII single quotes")
	assert.NotContains(t, got, "\u2018")
	assert.NotContains(t, got, "\u2019")
}

// TestNormalizeCurlInput_CurlExe verifies that a lowercase "curl.exe" prefix
// is normalised to "curl".
func TestNormalizeCurlInput_CurlExe(t *testing.T) {
	input := `curl.exe https://api.example.com/graphql -X GET`

	got, err := curl.NormalizeCurlInput(input)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(got, "curl "),
		"curl.exe must be normalised to curl; got: %q", got)
	assert.NotContains(t, got, "curl.exe")
}

// TestNormalizeCurlInput_CurlExeCaseInsensitive verifies that "curl.exe"
// normalisation is case-insensitive (e.g. CURL.EXE, Curl.Exe).
func TestNormalizeCurlInput_CurlExeCaseInsensitive(t *testing.T) {
	cases := []string{
		`CURL.EXE https://api.example.com/graphql -X GET`,
		`Curl.Exe https://api.example.com/graphql -X GET`,
		`curl.EXE https://api.example.com/graphql -X GET`,
	}
	for _, input := range cases {
		got, err := curl.NormalizeCurlInput(input)
		require.NoError(t, err, "input: %q", input)
		assert.True(t, strings.HasPrefix(got, "curl "),
			"curl.exe variant must normalise to 'curl '; got: %q", got)
	}
}

// TestNormalizeCurlInput_UnbalancedSingleQuote verifies that an unterminated
// single-quoted string produces an explicit error and does not panic.
func TestNormalizeCurlInput_UnbalancedSingleQuote(t *testing.T) {
	_, err := curl.NormalizeCurlInput(`curl 'https://example.com`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unterminated")
}

// TestNormalizeCurlInput_UnbalancedDoubleQuote verifies that an unterminated
// double-quoted string produces an explicit error and does not panic.
func TestNormalizeCurlInput_UnbalancedDoubleQuote(t *testing.T) {
	_, err := curl.NormalizeCurlInput(`curl "https://example.com`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unterminated")
}

// TestNormalizeCurlInput_WindowsEscapedJSON verifies that a Windows CMD-style
// command with a double-quoted JSON body (inner quotes escaped as \") does not
// panic and is accepted without error.
func TestNormalizeCurlInput_WindowsEscapedJSON(t *testing.T) {
	cmd := `curl "https://api.example.com/graphql"` +
		` -H "Content-Type: application/json"` +
		` -d "{\"operationName\":\"GetUser\",\"variables\":{\"id\":\"42\"}}"`

	got, err := curl.NormalizeCurlInput(cmd)
	require.NoError(t, err, "Windows-escaped JSON must not cause an error")
	assert.NotEmpty(t, got)
}

// TestNormalizeCurlInput_MixedQuotingStyles verifies that a command mixing
// single-quoted and double-quoted arguments is accepted without error.
func TestNormalizeCurlInput_MixedQuotingStyles(t *testing.T) {
	cmd := `curl 'https://api.example.com/graphql'` +
		` -H "Content-Type: application/json"` +
		` -d '{"query":"{ __typename }"}'`

	got, err := curl.NormalizeCurlInput(cmd)
	require.NoError(t, err, "mixed quoting styles must not cause an error")
	assert.NotEmpty(t, got)
}

// TestNormalizeCurlInput_PreservesJSONEscapeSequences verifies that ASCII JSON
// escape sequences (e.g. the six-character sequence \u201C) are not affected
// by smart-quote normalisation, which only targets actual Unicode code points.
func TestNormalizeCurlInput_PreservesJSONEscapeSequences(t *testing.T) {
	// The single-quoted body contains the ASCII string \u201C — six bytes,
	// not the Unicode character U+201C — and must pass through unchanged.
	input := `curl https://api.example.com -d '{"key":"\u201C"}'`

	got, err := curl.NormalizeCurlInput(input)
	require.NoError(t, err)
	assert.Contains(t, got, `\u201C`,
		"ASCII JSON escape sequences must be preserved verbatim")
}

// TestNormalizeCurlInput_WindowsCMDEscapedQuotes verifies that Windows CMD
// escape sequences for quotes (^") are correctly normalized to literal quotes.
func TestNormalizeCurlInput_WindowsCMDEscapedQuotes(t *testing.T) {
	input := `curl ^"https://api.example.com/graphql^" -X GET`

	got, err := curl.NormalizeCurlInput(input)
	require.NoError(t, err)
	// After normalization, ^" should become "
	assert.Contains(t, got, `"https://api.example.com/graphql"`)
	assert.NotContains(t, got, `^"`)
}

// TestNormalizeCurlInput_WindowsCMDEscapedCarets verifies that Windows CMD
// escape sequences for carets (^^) are correctly normalized to literal carets.
func TestNormalizeCurlInput_WindowsCMDEscapedCarets(t *testing.T) {
	input := `curl "https://api.example.com" -H "sec-ch-ua: ^^"Not:A-Brand^^";v=^^"99^^""`

	got, err := curl.NormalizeCurlInput(input)
	require.NoError(t, err)
	// After normalization, ^^ should become ^
	assert.Contains(t, got, `"Not:A-Brand";v="99"`)
	assert.NotContains(t, got, `^^"`)
}

// TestNormalizeCurlInput_ComplexWindowsCMDEscapes verifies that a realistic
// curl command with complex Windows CMD escaping is normalized correctly.
// This is the real-world case of a curl command copied from a Windows browser.
func TestNormalizeCurlInput_ComplexWindowsCMDEscapes(t *testing.T) {
	// Real-world curl command with Windows CMD escaping
	input := `curl ^"https://api.escuelajs.co/graphql^" ^ ` +
		`-H ^"accept: application/json^" ^ ` +
		`-H ^"sec-ch-ua: ^^"Not:A-Brand^^";v=^^"99^^"^" ^ ` +
		`--data-raw ^"^{^^"query^^":^^"{ user }^^"^}^"`

	got, err := curl.NormalizeCurlInput(input)
	require.NoError(t, err)

	// Verify that all escape sequences are resolved
	assert.Contains(t, got, `"https://api.escuelajs.co/graphql"`)
	assert.Contains(t, got, `"accept: application/json"`)
	assert.Contains(t, got, `"Not:A-Brand";v="99"`)
	assert.NotContains(t, got, `^"`)
	assert.NotContains(t, got, `^^"`)

	// Verify it doesn't error and contains expected structure
	assert.NotEmpty(t, got)
}

// TestParse_WindowsCMDEscapedRequest verifies that Parse can handle a
// realistic curl command with Windows CMD escape sequences and extract
// all components correctly.
func TestParse_WindowsCMDEscapedRequest(t *testing.T) {
	cmd := `curl ^"https://api.example.com/graphql^" ^ ` +
		`-H ^"Content-Type: application/json^" ^ ` +
		`--data-raw ^"^{^^"query^^":^^"{ __typename }^^"^}^"`

	pr, err := curl.Parse(cmd)
	require.NoError(t, err)

	assert.Equal(t, "POST", pr.Method) // inferred from body
	assert.Equal(t, "https://api.example.com/graphql", pr.URL)
	assert.Equal(t, "application/json", pr.Headers["Content-Type"])
	assert.Equal(t, `{"query":"{ __typename }"}`, pr.Body)
}

// ---------------------------------------------------------------------------
// End-to-end Parse tests exercising the new normalisation path
// ---------------------------------------------------------------------------

// TestParse_CurlExe verifies that Parse accepts a command beginning with
// "curl.exe" (as commonly used on Windows) and parses it correctly.
func TestParse_CurlExe(t *testing.T) {
	cmd := `curl.exe -X GET 'https://api.example.com/graphql' -H 'Accept: application/json'`

	pr, err := curl.Parse(cmd)
	require.NoError(t, err)

	assert.Equal(t, "GET", pr.Method)
	assert.Equal(t, "https://api.example.com/graphql", pr.URL)
	assert.Equal(t, "application/json", pr.Headers["Accept"])
}

// TestParse_SmartQuotes verifies that a command whose URL and header values
// are surrounded by typographic quotes (as pasted from a word processor or
// messaging app) is parsed correctly after normalisation.
func TestParse_SmartQuotes(t *testing.T) {
	// U+201C / U+201D wrap the URL; U+2018 / U+2019 wrap the header value.
	cmd := "curl \u201Chttps://api.example.com/graphql\u201D" +
		" -X POST" +
		" -H \u201CContent-Type: application/json\u201D" +
		" -d \u2018{\"query\":\"{ __typename }\"}\u2019"

	pr, err := curl.Parse(cmd)
	require.NoError(t, err)

	assert.Equal(t, "POST", pr.Method)
	assert.Equal(t, "https://api.example.com/graphql", pr.URL)
	assert.Equal(t, "application/json", pr.Headers["Content-Type"])
	assert.Equal(t, `{"query":"{ __typename }"}`, pr.Body)
}

// ---------------------------------------------------------------------------
// ANSI-C Quoting Tests ($'...')
// ---------------------------------------------------------------------------

// TestParse_ANSICQuotedMethod verifies that -X with ANSI-C quoting is parsed correctly.
func TestParse_ANSICQuotedMethod(t *testing.T) {
	cmd := "curl -X $'POST' https://api.example.com/graphql"

	pr, err := curl.Parse(cmd)
	require.NoError(t, err)

	assert.Equal(t, "POST", pr.Method)
	assert.Equal(t, "https://api.example.com/graphql", pr.URL)
}

// TestParse_ANSICQuotedURL verifies that an ANSI-C quoted URL is parsed correctly.
func TestParse_ANSICQuotedURL(t *testing.T) {
	cmd := "curl $'https://api.example.com/graphql' -X GET"

	pr, err := curl.Parse(cmd)
	require.NoError(t, err)

	assert.Equal(t, "GET", pr.Method)
	assert.Equal(t, "https://api.example.com/graphql", pr.URL)
}

// TestParse_ANSICQuotedHeader verifies that -H with ANSI-C quoting is parsed correctly.
func TestParse_ANSICQuotedHeader(t *testing.T) {
	cmd := "curl -X POST https://api.example.com/graphql -H $'Content-Type: application/json'"

	pr, err := curl.Parse(cmd)
	require.NoError(t, err)

	assert.Equal(t, "POST", pr.Method)
	assert.Equal(t, "https://api.example.com/graphql", pr.URL)
	assert.Equal(t, "application/json", pr.Headers["Content-Type"])
}

// TestParse_ANSICQuotedBody verifies that -d with ANSI-C quoting and escape sequences is parsed correctly.
func TestParse_ANSICQuotedBody(t *testing.T) {
	// The body contains a literal newline represented as \n
	cmd := `curl -X POST https://api.example.com/graphql -H 'Content-Type: application/json' -d $'{"query":"query (\n{ __typename }"}'`

	pr, err := curl.Parse(cmd)
	require.NoError(t, err)

	assert.Equal(t, "POST", pr.Method)
	assert.Equal(t, "https://api.example.com/graphql", pr.URL)
	assert.Equal(t, "application/json", pr.Headers["Content-Type"])
	// Verify that \n in ANSI-C string becomes an actual newline character
	assert.Contains(t, pr.Body, "query (\n{ __typename }")
}

// TestParse_ANSICQuotedBackslash verifies that \\ in ANSI-C strings becomes a single backslash.
func TestParse_ANSICQuotedBackslash(t *testing.T) {
	cmd := `curl https://api.example.com -d $'{"path":"C:\\Users\\test"}'`

	pr, err := curl.Parse(cmd)
	require.NoError(t, err)

	assert.Equal(t, `{"path":"C:\Users\test"}`, pr.Body)
}

// TestParse_ANSICQuotedEscapedQuote verifies that \" in ANSI-C strings becomes a double quote.
func TestParse_ANSICQuotedEscapedQuote(t *testing.T) {
	cmd := `curl https://api.example.com -d $'{"msg":"Say \\"Hello\\""}'`

	pr, err := curl.Parse(cmd)
	require.NoError(t, err)

	assert.Equal(t, `{"msg":"Say "Hello""}`, pr.Body)
}

// TestParse_ANSICQuotedMultipleHeaders verifies that multiple headers with ANSI-C quoting are all collected.
func TestParse_ANSICQuotedMultipleHeaders(t *testing.T) {
	cmd := "curl -X POST https://api.example.com/graphql " +
		"-H $'Content-Type: application/json' " +
		"-H $'Authorization: Bearer token123' " +
		"-H $'X-Request-ID: req-456'"

	pr, err := curl.Parse(cmd)
	require.NoError(t, err)

	assert.Equal(t, "POST", pr.Method)
	assert.Equal(t, "https://api.example.com/graphql", pr.URL)
	assert.Equal(t, "application/json", pr.Headers["Content-Type"])
	assert.Equal(t, "Bearer token123", pr.Headers["Authorization"])
	assert.Equal(t, "req-456", pr.Headers["X-Request-ID"])
}

// TestParse_ANSICQuotedTab verifies that \t in ANSI-C strings becomes a tab character.
func TestParse_ANSICQuotedTab(t *testing.T) {
	cmd := `curl https://api.example.com -d $'line1\tline2'`

	pr, err := curl.Parse(cmd)
	require.NoError(t, err)

	assert.Equal(t, "line1\tline2", pr.Body)
}

// TestParse_ANSICQuotedCarriageReturn verifies that \r in ANSI-C strings becomes a CR character.
func TestParse_ANSICQuotedCarriageReturn(t *testing.T) {
	cmd := `curl https://api.example.com -d $'line1\rline2'`

	pr, err := curl.Parse(cmd)
	require.NoError(t, err)

	assert.Equal(t, "line1\rline2", pr.Body)
}

// TestParse_ANSICQuotedComplexCommand verifies that a realistic curl command with
// multiple ANSI-C quoted arguments (similar to the user's GitLab example) is parsed correctly.
func TestParse_ANSICQuotedComplexCommand(t *testing.T) {
	cmd := `curl --path-as-is -i -s -k -X $'POST' \
    -H $'Host: gitlab.com' -H $'Content-Type: application/json' \
    -H $'X-Csrf-Token: token123' \
    --data-binary $'{"query":"{ __schema { __typename } }"}' \
    $'https://gitlab.com/api/graphql'`

	pr, err := curl.Parse(cmd)
	require.NoError(t, err)

	assert.Equal(t, "POST", pr.Method)
	assert.Equal(t, "https://gitlab.com/api/graphql", pr.URL)
	assert.Equal(t, "gitlab.com", pr.Headers["Host"])
	assert.Equal(t, "application/json", pr.Headers["Content-Type"])
	assert.Equal(t, "token123", pr.Headers["X-Csrf-Token"])
	assert.Equal(t, `{"query":"{ __schema { __typename } }"}`, pr.Body)
}

// ---------------------------------------------------------------------------
// Edge cases and error handling for ANSI-C quoting
// ---------------------------------------------------------------------------

// TestParse_ANSICQuotedUnterminatedString verifies that an unterminated ANSI-C quoted string produces an error.
func TestParse_ANSICQuotedUnterminatedString(t *testing.T) {
	cmd := `curl https://api.example.com -d $'{"query":"incomplete`

	_, err := curl.Parse(cmd)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ANSI-C")
}

// TestParse_MixedQuotingStyles verifies that a command mixing single, double, and ANSI-C quoting works.
func TestParse_MixedQuotingStyles(t *testing.T) {
	cmd := `curl 'https://api.example.com' -H "Content-Type: application/json" -H $'Authorization: Bearer token'`

	pr, err := curl.Parse(cmd)
	require.NoError(t, err)

	assert.Equal(t, "https://api.example.com", pr.URL)
	assert.Equal(t, "application/json", pr.Headers["Content-Type"])
	assert.Equal(t, "Bearer token", pr.Headers["Authorization"])
}

// TestParse_ANSICQuotedCookieFlag verifies that -b (cookies) flag with ANSI-C quoting is handled.
func TestParse_ANSICQuotedCookieFlag(t *testing.T) {
	cmd := `curl -b $'sessionid=abc123' https://api.example.com`

	pr, err := curl.Parse(cmd)
	require.NoError(t, err)

	assert.Equal(t, "https://api.example.com", pr.URL)
	// The -b flag is unknown, so its argument should be skipped and not affect URL detection
}

// TestNormalizeCurlInput_ANSICQuotes verifies that ANSI-C quoted strings are recognized during normalization.
func TestNormalizeCurlInput_ANSICQuotes(t *testing.T) {
	cmd := `curl $'https://api.example.com' -X GET`

	got, err := curl.NormalizeCurlInput(cmd)
	require.NoError(t, err, "ANSI-C quoted strings must not cause an error")
	assert.NotEmpty(t, got)
	assert.Contains(t, got, "api.example.com")
}
