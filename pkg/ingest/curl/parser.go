// Package curl provides a pure-Go parser for raw curl command strings.
//
// It converts Bash and Windows CMD curl commands into a structured
// domain.CurlRequest, preserving method, URL, headers, and body without
// executing any shell commands.
package curl

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/gqls-cli/gqls/pkg/domain"
)

// NormalizeCurlInput performs pre-normalization of a raw curl command string
// before tokenization and parsing.
//
// It applies the following transformations in order:
//  1. Joins Bash line continuations (\ + newline) into a single space.
//  2. Joins Windows CMD line continuations (^ + newline) into a single space.
//  3. Normalises Windows CMD inline escape sequences (^" → ", ^^ → ^).
//  4. Replaces Unicode typographic/smart quote characters with their ASCII
//     equivalents (" " → ", ' ' → '), preserving all JSON escape sequences.
//  5. Normalises "curl.exe" (any case) to "curl" so the downstream token
//     check accepts Windows-style invocations.
//  6. Validates that all single and double quote characters are balanced,
//     applying the same quoting rules as the tokenizer.
//
// It returns the normalised single-line string, or an error if the quote
// structure is unbalanced.
func NormalizeCurlInput(raw string) (string, error) {
	// 1 & 2. Join Bash (\) and CMD (^) line continuations.
	s := normalizeLineContinuations(raw)

	// 3. Normalise Windows CMD inline escape sequences (^" → ", ^^ → ^).
	s = normalizeWindowsCMDEscapes(s)

	// 4. Replace smart/typographic quotes with ASCII equivalents.
	s = normalizeSmartQuotes(s)

	// 5. Normalise "curl.exe" → "curl" so the tokeniser's first-token check
	//    accepts Windows-style invocations regardless of case.
	s = strings.TrimSpace(s)
	if len(s) >= len("curl.exe") && strings.EqualFold(s[:len("curl.exe")], "curl.exe") {
		s = "curl" + s[len("curl.exe"):]
	}

	// 6. Validate quote balance before handing off to the tokeniser.
	if err := checkQuoteBalance(s); err != nil {
		return "", err
	}

	return s, nil
}

// Parse converts a raw curl command string into a domain.CurlRequest.
//
// Supported features:
//   - Bash-style line continuations (trailing \)
//   - Windows CMD-style line continuations (trailing ^)
//   - Windows CMD inline escape sequences (^" → ", ^^ → ^, ^' → ')
//   - Single-quoted strings (Bash): literal content, no escape processing
//   - Double-quoted strings: backslash escapes for \", \\, \n, \t, \r
//   - ANSI-C quoted strings ($'...'): escape sequences like \n, \t, \\, \"
//   - Flags: -X / --request, -H / --header, -d / --data / --data-raw / --data-binary
//   - --url flag for explicit URL specification
//   - Method inference: POST when a body is present, GET otherwise
//   - Smart/typographic quotes are normalised to ASCII before tokenisation
//   - Windows "curl.exe" prefix is accepted and normalised to "curl"
//
// Unknown flags are silently skipped. If the token following an unknown flag
// does not start with "-" and does not look like an HTTP URL, it is treated as
// that flag's argument and also skipped.
func Parse(cmd string) (*domain.CurlRequest, error) {
	normalized, err := NormalizeCurlInput(cmd)
	if err != nil {
		return nil, err
	}

	tokens, err := tokenize(normalized)
	if err != nil {
		return nil, err
	}

	if len(tokens) == 0 {
		return nil, errors.New("curl: empty command")
	}

	if strings.ToLower(tokens[0]) != "curl" {
		return nil, fmt.Errorf("curl: command must begin with 'curl', got %q", tokens[0])
	}

	pr := &domain.CurlRequest{
		Headers: make(map[string]string),
	}

	for i := 1; i < len(tokens); {
		tok := tokens[i]

		switch tok {
		case "-X", "--request":
			if i+1 >= len(tokens) {
				return nil, fmt.Errorf("curl: %s requires a value", tok)
			}
			pr.Method = strings.ToUpper(tokens[i+1])
			i += 2

		case "-H", "--header":
			if i+1 >= len(tokens) {
				return nil, fmt.Errorf("curl: %s requires a value", tok)
			}
			k, v, herr := splitHeader(tokens[i+1])
			if herr != nil {
				return nil, herr
			}
			pr.Headers[k] = v
			i += 2

		case "-d", "--data", "--data-raw", "--data-binary":
			if i+1 >= len(tokens) {
				return nil, fmt.Errorf("curl: %s requires a value", tok)
			}
			pr.Body = tokens[i+1]
			i += 2

		case "--url":
			if i+1 >= len(tokens) {
				return nil, errors.New("curl: --url requires a value")
			}
			pr.URL = tokens[i+1]
			i += 2

		default:
			if !strings.HasPrefix(tok, "-") {
				// Positional argument: the first one is the URL.
				if pr.URL == "" {
					pr.URL = tok
				}
				i++
			} else {
				// Unknown flag. Peek ahead: if the next token is not a flag
				// and not an HTTP URL (i.e. it looks like a flag argument),
				// skip it together with the flag itself.
				i++
				if i < len(tokens) {
					next := tokens[i]
					if !strings.HasPrefix(next, "-") && !isHTTPURL(next) {
						i++ // skip the unknown flag's argument
					}
				}
			}
		}
	}

	if pr.URL == "" {
		return nil, errors.New("curl: no URL found in command")
	}

	// Infer method when -X / --request was not supplied.
	if pr.Method == "" {
		if pr.Body != "" {
			pr.Method = "POST"
		} else {
			pr.Method = "GET"
		}
	}

	return pr, nil
}

// isHTTPURL reports whether s begins with http:// or https://.
func isHTTPURL(s string) bool {
	ls := strings.ToLower(s)
	return strings.HasPrefix(ls, "http://") || strings.HasPrefix(ls, "https://")
}

// isANSICQuoteStart reports whether s at position i starts an ANSI-C quoted string ($').
func isANSICQuoteStart(s string, i int) bool {
	return i+1 < len(s) && s[i] == '$' && s[i+1] == '\''
}

// normalizeLineContinuations removes Bash (\) and Windows CMD (^) line-
// continuation characters, joining the continued line with the next using a
// single space. CRLF line endings are handled transparently.
func normalizeLineContinuations(s string) string {
	lines := strings.Split(s, "\n")
	var b strings.Builder
	for i, line := range lines {
		// Strip trailing carriage-return that may be present in CRLF content.
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimRight(line, " \t")

		switch {
		case strings.HasSuffix(trimmed, "\\"):
			// Bash continuation: remove trailing backslash, glue next line.
			b.WriteString(trimmed[:len(trimmed)-1])
			b.WriteByte(' ')
		case strings.HasSuffix(trimmed, "^"):
			// CMD continuation: remove trailing caret, glue next line.
			b.WriteString(trimmed[:len(trimmed)-1])
			b.WriteByte(' ')
		default:
			b.WriteString(line)
			// Insert a space between non-continued lines so tokens on adjacent
			// lines remain properly delimited after joining.
			if i < len(lines)-1 {
				b.WriteByte(' ')
			}
		}
	}
	return b.String()
}

// normalizeSmartQuotes replaces Unicode typographic quotation marks with their
// ASCII equivalents so the tokenizer can handle them uniformly.
//
// Replacements performed:
//
//	U+201C (") → "   LEFT  DOUBLE QUOTATION MARK
//	U+201D (") → "   RIGHT DOUBLE QUOTATION MARK
//	U+2018 (') → '   LEFT  SINGLE QUOTATION MARK
//	U+2019 (') → '   RIGHT SINGLE QUOTATION MARK
//
// JSON escape sequences (e.g. \u201C) are unaffected because they consist
// entirely of ASCII characters; only the actual Unicode code points are
// replaced.
func normalizeSmartQuotes(s string) string {
	return strings.NewReplacer(
		"\u201C", `"`, // "  left double quotation mark
		"\u201D", `"`, // "  right double quotation mark
		"\u2018", `'`, // '  left single quotation mark
		"\u2019", `'`, // '  right single quotation mark
	).Replace(s)
}

// normalizeWindowsCMDEscapes processes Windows CMD escape sequences.
//
// In Windows CMD, the caret (^) is the escape character. This function
// handles the following escape sequences that can appear inline (not just
// at line endings):
//
//	^^ → ^   (escaped caret: literal caret character)
//	^" → "   (escaped double quote: literal double quote character)
//	^' → '   (escaped single quote: literal single quote character)
//
// This normalization allows curl commands copied from Windows browsers to be
// parsed correctly, as browser developer tools often escape quotes and carets
// when exporting curl commands from Windows systems.
func normalizeWindowsCMDEscapes(s string) string {
	var result strings.Builder
	i := 0
	for i < len(s) {
		if s[i] == '^' && i+1 < len(s) {
			next := s[i+1]
			switch next {
			case '^':
				// ^^ becomes ^
				result.WriteByte('^')
				i += 2
			case '"':
				// ^" becomes "
				result.WriteByte('"')
				i += 2
			case '\'':
				// ^' becomes '
				result.WriteByte('\'')
				i += 2
			default:
				// Not a recognized escape sequence; keep both characters
				result.WriteByte(s[i])
				i++
			}
		} else {
			result.WriteByte(s[i])
			i++
		}
	}
	return result.String()
}

// checkQuoteBalance scans s and reports whether all single and double quote
// characters are properly paired.
//
// The same quoting semantics as tokenize are applied:
//   - Single-quoted regions: fully literal; the only closer is an unescaped '.
//   - Double-quoted regions: \\ and \" are recognised escape sequences; any
//     other character (including a bare ") closes the region.
//   - ANSI-C quoted regions ($'...'): \\ and \' are recognised escape sequences;
//     any other character (including a bare ') closes the region.
//
// The function returns the first unterminated-quote error encountered, or nil
// when all quotes are balanced.
func checkQuoteBalance(s string) error {
	i := 0
	for i < len(s) {
		switch {
		case isANSICQuoteStart(s, i):
			// ANSI-C quoted region: consume until the matching closing quote.
			// Escape sequences are recognised: \\ and \'
			i += 2 // skip $'
			for i < len(s) && s[i] != '\'' {
				if s[i] == '\\' && i+1 < len(s) {
					i += 2 // skip the escape character and the escaped byte
				} else {
					i++
				}
			}
			if i >= len(s) {
				return errors.New("curl: unterminated ANSI-C quoted string")
			}
			i++ // skip closing '

		case s[i] == '\'':
			// Single-quoted region: consume until the matching closing quote.
			// No escape sequences are recognised inside single quotes.
			i++ // skip opening '
			for i < len(s) && s[i] != '\'' {
				i++
			}
			if i >= len(s) {
				return errors.New("curl: unterminated single-quoted string")
			}
			i++ // skip closing '

		case s[i] == '"':
			// Double-quoted region: honour \\ and \" escape sequences so that
			// a \" inside a JSON payload is not mistaken for a closing quote.
			i++ // skip opening "
			for i < len(s) && s[i] != '"' {
				if s[i] == '\\' && i+1 < len(s) {
					i += 2 // skip the escape character and the escaped byte
				} else {
					i++
				}
			}
			if i >= len(s) {
				return errors.New("curl: unterminated double-quoted string")
			}
			i++ // skip closing "

		default:
			i++
		}
	}
	return nil
}

// processANSICEscapes processes escape sequences inside ANSI-C quoted strings ($'...').
// It handles the following escape sequences:
//   - \n → newline
//   - \t → tab
//   - \r → carriage return
//   - \\ → backslash
//   - \" → double quote
//   - \' → single quote
//   - Any other \X is preserved as-is to avoid losing data.
func processANSICEscapes(s string) string {
	var result strings.Builder
	i := 0
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case 'n':
				result.WriteByte('\n')
			case 't':
				result.WriteByte('\t')
			case 'r':
				result.WriteByte('\r')
			case '\\':
				result.WriteByte('\\')
			case '"':
				result.WriteByte('"')
			case '\'':
				result.WriteByte('\'')
			default:
				// Unknown escape: preserve verbatim
				result.WriteByte('\\')
				result.WriteByte(s[i+1])
			}
			i += 2
		} else {
			result.WriteByte(s[i])
			i++
		}
	}
	return result.String()
}

// tokenize splits a (normalised) shell command string into tokens.
//
// Quoting rules:
//   - Single-quoted strings (Bash): all bytes are literal; no escaping at all.
//   - Double-quoted strings: \", \\, \n, \t, \r are resolved; any other \X is
//     preserved as-is (\X) to avoid losing data in CMD-style commands.
//   - ANSI-C quoted strings ($'...'): \n, \t, \r, \\, \", \' are resolved;
//     any other \X is preserved as-is.
//   - Unquoted segments are delimited by Unicode whitespace.
//
// Adjacent quoted and unquoted segments (no whitespace between them) are
// concatenated into a single token, matching POSIX shell quoting behaviour.
func tokenize(s string) ([]string, error) {
	var tokens []string
	var cur strings.Builder
	inToken := false

	i := 0
	for i < len(s) {
		ch := rune(s[i])

		switch {
		case ch == '\'' && !isANSICQuoteStart(s, i):
			// Single-quoted string: consume until the matching closing quote.
			inToken = true
			i++ // skip opening '
			for i < len(s) && s[i] != '\'' {
				cur.WriteByte(s[i])
				i++
			}
			if i >= len(s) {
				return nil, errors.New("curl: unterminated single-quoted string")
			}
			i++ // skip closing '

		case isANSICQuoteStart(s, i):
			// ANSI-C quoted string ($'...'): process escape sequences.
			inToken = true
			i += 2 // skip $'
			var quoted strings.Builder
			for i < len(s) && s[i] != '\'' {
				quoted.WriteByte(s[i])
				i++
			}
			if i >= len(s) {
				return nil, errors.New("curl: unterminated ANSI-C quoted string")
			}
			// Process ANSI-C escape sequences and write to current token
			cur.WriteString(processANSICEscapes(quoted.String()))
			i++ // skip closing '

		case ch == '"':
			// Double-quoted string: process recognised backslash escapes.
			inToken = true
			i++ // skip opening "
			for i < len(s) && s[i] != '"' {
				if s[i] == '\\' && i+1 < len(s) {
					switch s[i+1] {
					case '"':
						cur.WriteByte('"')
					case '\\':
						cur.WriteByte('\\')
					case 'n':
						cur.WriteByte('\n')
					case 't':
						cur.WriteByte('\t')
					case 'r':
						cur.WriteByte('\r')
					default:
						// Unknown escape: preserve verbatim so no data is lost.
						cur.WriteByte('\\')
						cur.WriteByte(s[i+1])
					}
					i += 2
				} else {
					cur.WriteByte(s[i])
					i++
				}
			}
			if i >= len(s) {
				return nil, errors.New("curl: unterminated double-quoted string")
			}
			i++ // skip closing "

		case unicode.IsSpace(ch):
			// Whitespace ends the current token (if any).
			if inToken || cur.Len() > 0 {
				tokens = append(tokens, cur.String())
				cur.Reset()
				inToken = false
			}
			i++

		default:
			inToken = true
			cur.WriteByte(s[i])
			i++
		}
	}

	// Flush any trailing token.
	if inToken || cur.Len() > 0 {
		tokens = append(tokens, cur.String())
	}

	return tokens, nil
}

// splitHeader splits a "Key: Value" header string on the first colon,
// returning trimmed key and value components.
func splitHeader(h string) (string, string, error) {
	idx := strings.Index(h, ":")
	if idx < 0 {
		return "", "", fmt.Errorf("curl: malformed header %q: missing ':'", h)
	}
	return strings.TrimSpace(h[:idx]), strings.TrimSpace(h[idx+1:]), nil
}
