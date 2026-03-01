package transport

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDo_RequestBodyReadableAfterDo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := NewClient(5*time.Second, 100, nil)

	bodyContent := `{"query":"{ __typename }"}`
	req, err := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader(bodyContent))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// The request body must still be readable after Do() returns.
	require.NotNil(t, req.Body, "request body should not be nil after Do")
	got, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	assert.Equal(t, bodyContent, string(got), "request body should be re-readable after Do")
}

func TestDo_AuthHeaderInjected(t *testing.T) {
	var receivedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	headers := map[string]string{
		"Authorization": "Bearer test-token",
	}
	client := NewClient(5*time.Second, 100, headers)

	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	require.NoError(t, err)

	_, err = client.Do(req)
	require.NoError(t, err)

	assert.Equal(t, "Bearer test-token", receivedAuth, "Authorization header should be injected")
}

func TestDo_AuthHeaderOverridesRequestHeader(t *testing.T) {
	var receivedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := NewClient(5*time.Second, 100, map[string]string{
		"Authorization": "Bearer injected",
	})

	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer original")

	_, err = client.Do(req)
	require.NoError(t, err)

	assert.Equal(t, "Bearer injected", receivedAuth, "client Authorization must override request Authorization")
}

func TestDo_DefaultHeaderNotOverridesRequestHeader(t *testing.T) {
	var receivedHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeader = r.Header.Get("X-Custom")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := NewClient(5*time.Second, 100, map[string]string{
		"X-Custom": "default-value",
	})

	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	require.NoError(t, err)
	req.Header.Set("X-Custom", "request-value")

	_, err = client.Do(req)
	require.NoError(t, err)

	assert.Equal(t, "request-value", receivedHeader, "non-auth headers should not override request headers")
}

func TestDo_RateLimiterDelaysRequests(t *testing.T) {
	callTimes := make([]time.Time, 0, 3)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callTimes = append(callTimes, time.Now())
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// 2 requests per second → at least ~500 ms between requests.
	client := NewClient(5*time.Second, 2, nil)

	for i := 0; i < 3; i++ {
		req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
		require.NoError(t, err)
		_, err = client.Do(req)
		require.NoError(t, err)
	}

	require.Len(t, callTimes, 3)
	// The total duration for 3 requests at 2 rps should be at least ~1 second.
	elapsed := callTimes[2].Sub(callTimes[0])
	assert.GreaterOrEqual(t, elapsed, 400*time.Millisecond,
		"rate limiter should introduce delay between requests")
}

func TestDo_TimeoutRespected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Simulate a very slow response.
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Timeout shorter than server response delay.
	client := NewClient(50*time.Millisecond, 100, nil)

	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	require.NoError(t, err)

	_, err = client.Do(req)
	require.Error(t, err, "request should fail due to timeout")
}

func TestDo_BodyNilNoError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	client := NewClient(5*time.Second, 100, nil)
	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	assert.Equal(t, []byte{}, resp.Body)
}

func TestDo_ResponseBodyCaptured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":null}`))
	}))
	defer srv.Close()

	client := NewClient(5*time.Second, 100, nil)
	req, err := http.NewRequest(http.MethodGet, srv.URL, bytes.NewReader(nil))
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, `{"data":null}`, string(resp.Body))
}
