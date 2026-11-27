package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestFallbackAndCacheHit(t *testing.T) {
	t.Parallel()

	var firstRequests atomic.Int32
	first := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		firstRequests.Add(1)
		http.Error(w, "broken", http.StatusServiceUnavailable)
	}))
	defer first.Close()

	var secondRequests atomic.Int32
	second := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondRequests.Add(1)
		if r.URL.Path != "/gnu/gmp/gmp-6.3.0.tar.xz" {
			t.Fatalf("unexpected upstream path %q", r.URL.Path)
		}

		_, _ = io.WriteString(w, "archive")
	}))
	defer second.Close()

	mirror := newTestMirror(t, time.Hour, first, second)
	proxy := httptest.NewServer(mirror)
	defer proxy.Close()

	response := get(t, proxy.URL+"/gnu/gmp/gmp-6.3.0.tar.xz")
	assertResponse(t, response, http.StatusOK, "MISS", "archive")

	response = get(t, proxy.URL+"/gnu/gmp/gmp-6.3.0.tar.xz")
	assertResponse(t, response, http.StatusOK, "HIT", "archive")

	if got := firstRequests.Load(); got != 1 {
		t.Fatalf("first upstream requests = %d, want 1", got)
	}
	if got := secondRequests.Load(); got != 1 {
		t.Fatalf("second upstream requests = %d, want 1", got)
	}
}

func TestExpiredCacheServesStaleOnFailure(t *testing.T) {
	t.Parallel()

	var fail atomic.Bool
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail.Load() {
			http.Error(w, "broken", http.StatusServiceUnavailable)

			return
		}

		_, _ = io.WriteString(w, "archive")
	}))
	defer upstream.Close()

	mirror := newTestMirror(t, time.Hour, upstream)
	now := time.Unix(1_700_000_000, 0)
	mirror.now = func() time.Time { return now }
	proxy := httptest.NewServer(mirror)
	defer proxy.Close()

	response := get(t, proxy.URL+"/gnu/gmp/gmp-6.3.0.tar.xz")
	assertResponse(t, response, http.StatusOK, "MISS", "archive")

	now = now.Add(2 * time.Hour)
	fail.Store(true)

	response = get(t, proxy.URL+"/gnu/gmp/gmp-6.3.0.tar.xz")
	assertResponse(t, response, http.StatusOK, "STALE", "archive")
}

func TestRejectsInvalidRequests(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewTLSServer(http.NotFoundHandler())
	defer upstream.Close()

	mirror := newTestMirror(t, time.Hour, upstream)

	tests := []struct {
		method string
		target string
		status int
	}{
		{http.MethodGet, "/not-gnu/archive.tar.xz", http.StatusBadRequest},
		{http.MethodGet, "/gnu/", http.StatusBadRequest},
		{http.MethodGet, "/gnu//archive.tar.xz", http.StatusBadRequest},
		{http.MethodGet, "/gnu/../archive.tar.xz", http.StatusBadRequest},
		{http.MethodGet, "/gnu/gmp/archive.tar.xz?download=1", http.StatusBadRequest},
		{http.MethodPost, "/gnu/gmp/archive.tar.xz", http.StatusMethodNotAllowed},
	}

	for _, test := range tests {
		t.Run(test.method+" "+test.target, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.target, nil)
			response := httptest.NewRecorder()
			mirror.ServeHTTP(response, request)

			if response.Code != test.status {
				t.Fatalf("status = %d, want %d", response.Code, test.status)
			}
		})
	}
}

func TestConcurrentColdRequestsFetchOnce(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	release := make(chan struct{})
	var requests atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			close(started)
		}
		<-release
		_, _ = io.WriteString(w, "archive")
	}))
	defer upstream.Close()

	mirror := newTestMirror(t, time.Hour, upstream)
	proxy := httptest.NewServer(mirror)
	defer proxy.Close()

	const requestCount = 8
	var waitGroup sync.WaitGroup
	waitGroup.Add(requestCount)
	errors := make(chan error, requestCount)

	for range requestCount {
		go func() {
			defer waitGroup.Done()

			response, err := http.Get(proxy.URL + "/gnu/gmp/gmp-6.3.0.tar.xz")
			if err != nil {
				errors <- err

				return
			}
			defer response.Body.Close()

			if response.StatusCode != http.StatusOK {
				errors <- &statusError{status: response.StatusCode}
			}
		}()
	}

	<-started
	close(release)
	waitGroup.Wait()
	close(errors)

	for err := range errors {
		t.Fatal(err)
	}

	if got := requests.Load(); got != 1 {
		t.Fatalf("upstream requests = %d, want 1", got)
	}
}

type statusError struct {
	status int
}

func (err *statusError) Error() string {
	return http.StatusText(err.status)
}

func newTestMirror(t *testing.T, ttl time.Duration, upstreams ...*httptest.Server) *mirrorServer {
	t.Helper()

	rawUpstreams := make([]string, 0, len(upstreams))
	for _, upstream := range upstreams {
		rawUpstreams = append(rawUpstreams, upstream.URL)
	}

	mirror, err := newMirrorServer(t.TempDir(), ttl, time.Second, rawUpstreams)
	if err != nil {
		t.Fatal(err)
	}

	for _, upstream := range upstreams {
		mirror.client = upstream.Client()
		mirror.client.Timeout = time.Second
	}

	return mirror
}

func get(t *testing.T, target string) *http.Response {
	t.Helper()

	response, err := http.Get(target)
	if err != nil {
		t.Fatal(err)
	}

	return response
}

func assertResponse(t *testing.T, response *http.Response, status int, cache, body string) {
	t.Helper()
	defer response.Body.Close()

	if response.StatusCode != status {
		t.Fatalf("status = %d, want %d", response.StatusCode, status)
	}
	if got := response.Header.Get("X-Cache"); got != cache {
		t.Fatalf("X-Cache = %q, want %q", got, cache)
	}

	contents, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(contents); got != body {
		t.Fatalf("body = %q, want %q", got, body)
	}
}
