package transport

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/coder/websocket"
)

// WSResult is the outcome of a single graphql-over-WebSocket subscription attempt.
type WSResult struct {
	// Subprotocol is the negotiated WebSocket subprotocol (e.g. "graphql-transport-ws").
	Subprotocol string
	// Acked is true when the server returned connection_ack.
	Acked bool
	// Subscribed is true when a subscribe/start frame was sent after the ack.
	Subscribed bool
	// NextPayload is the payload of the first next/data message (raw JSON), or nil.
	NextPayload json.RawMessage
	// Errored is true when the server returned an error/connection_error frame.
	Errored bool
	// ErrorPayload is the payload of an error frame, if any.
	ErrorPayload json.RawMessage
	// CloseCode is the WebSocket close code (e.g. 4401/4403), or -1 if not closed by code.
	CloseCode int
	// TimedOut is true when the wait window elapsed before a terminal message.
	TimedOut bool
	// Err is a transport/handshake error (dial failure, etc.). When set, the
	// endpoint was effectively unreachable for subscriptions.
	Err error
}

// wsMessage is a graphql-transport-ws / graphql-ws protocol frame.
type wsMessage struct {
	ID      string          `json:"id,omitempty"`
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// Subscribe opens a graphql-over-WebSocket connection to wsURL with the given
// headers, performs the connection_init → connection_ack → subscribe handshake,
// waits up to timeout for the first next/error/complete, then closes cleanly.
//
// It negotiates both the modern (graphql-transport-ws) and legacy (graphql-ws)
// subprotocols and adapts its frame vocabulary to whichever the server selects.
// The subscription is always terminated and the connection closed before return.
func Subscribe(parent context.Context, wsURL string, headers map[string]string, subscribeDoc string, timeout time.Duration) WSResult {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	hdr := http.Header{}
	for k, v := range headers {
		hdr.Set(k, v)
	}

	conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader:   hdr,
		Subprotocols: []string{"graphql-transport-ws", "graphql-ws"},
	})
	if err != nil {
		return WSResult{Err: err, CloseCode: closeCodeOf(err)}
	}
	conn.SetReadLimit(1 << 20) // 1 MiB
	defer conn.Close(websocket.StatusNormalClosure, "")

	res := WSResult{Subprotocol: conn.Subprotocol(), CloseCode: -1}

	// Legacy graphql-ws uses start/data/stop; modern graphql-transport-ws uses
	// subscribe/next/complete.
	subscribeType, dataType, completeType := "subscribe", "next", "complete"
	if conn.Subprotocol() == "graphql-ws" {
		subscribeType, dataType, completeType = "start", "data", "stop"
	}

	if err := writeWS(ctx, conn, wsMessage{Type: "connection_init"}); err != nil {
		res.Err = err
		return res
	}

	for {
		_, data, rerr := conn.Read(ctx)
		if rerr != nil {
			res.CloseCode = closeCodeOf(rerr)
			if ctx.Err() == context.DeadlineExceeded {
				res.TimedOut = true
			}
			return res
		}
		var m wsMessage
		if json.Unmarshal(data, &m) != nil {
			continue // ignore malformed frames
		}
		switch m.Type {
		case "connection_ack":
			res.Acked = true
			subDoc, _ := json.Marshal(map[string]string{"query": subscribeDoc})
			if err := writeWS(ctx, conn, wsMessage{ID: "1", Type: subscribeType, Payload: subDoc}); err != nil {
				res.Err = err
				return res
			}
			res.Subscribed = true
		case "ping":
			_ = writeWS(ctx, conn, wsMessage{Type: "pong"})
		case dataType: // "next" or "data"
			res.NextPayload = m.Payload
			_ = writeWS(ctx, conn, wsMessage{ID: "1", Type: completeType})
			return res
		case "error", "connection_error":
			res.Errored = true
			res.ErrorPayload = m.Payload
			return res
		case "complete":
			return res // server ended the subscription without delivering data
		}
	}
}

// writeWS marshals and writes a single protocol frame as a text message.
func writeWS(ctx context.Context, conn *websocket.Conn, m wsMessage) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return conn.Write(ctx, websocket.MessageText, b)
}

// closeCodeOf extracts a WebSocket close code from an error, or -1.
func closeCodeOf(err error) int {
	if status := websocket.CloseStatus(err); status != -1 {
		return int(status)
	}
	return -1
}
