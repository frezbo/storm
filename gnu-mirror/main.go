package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	defaultListenAddr = ":15008"
	defaultCacheDir   = "/var/cache/gnu-mirror"
	defaultCacheTTL   = 30 * 24 * time.Hour
	defaultTimeout    = 30 * time.Second
	defaultUpstreams  = "https://mirrors.kernel.org,https://mirror.csclub.uwaterloo.ca,https://mirrorservice.org/sites/ftp.gnu.org,https://ftp.gnu.org"
)

type fetchCall struct {
	done     chan struct{}
	upstream string
	err      error
}

type mirrorServer struct {
	cacheDir string
	cacheTTL time.Duration
	client   *http.Client
	now      func() time.Time
	upstream []*url.URL

	mu       sync.Mutex
	inflight map[string]*fetchCall
}

func main() {
	server, err := serverFromEnvironment()
	if err != nil {
		log.Fatal(err)
	}

	httpServer := &http.Server{
		Addr:              envOrDefault("LISTEN_ADDR", defaultListenAddr),
		Handler:           server,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if shutdownErr := httpServer.Shutdown(shutdownCtx); shutdownErr != nil {
			log.Printf("shutdown_error=%q", shutdownErr)
		}
	}()

	log.Printf("listen=%q cache_dir=%q cache_ttl=%q", httpServer.Addr, server.cacheDir, server.cacheTTL)

	if err = httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func serverFromEnvironment() (*mirrorServer, error) {
	cacheTTL, err := time.ParseDuration(envOrDefault("CACHE_TTL", defaultCacheTTL.String()))
	if err != nil {
		return nil, fmt.Errorf("parse CACHE_TTL: %w", err)
	}

	requestTimeout, err := time.ParseDuration(envOrDefault("UPSTREAM_TIMEOUT", defaultTimeout.String()))
	if err != nil {
		return nil, fmt.Errorf("parse UPSTREAM_TIMEOUT: %w", err)
	}

	return newMirrorServer(
		envOrDefault("CACHE_DIR", defaultCacheDir),
		cacheTTL,
		requestTimeout,
		strings.Split(envOrDefault("UPSTREAMS", defaultUpstreams), ","),
	)
}

func newMirrorServer(cacheDir string, cacheTTL, requestTimeout time.Duration, upstreams []string) (*mirrorServer, error) {
	if cacheTTL <= 0 {
		return nil, errors.New("CACHE_TTL must be positive")
	}

	if requestTimeout <= 0 {
		return nil, errors.New("UPSTREAM_TIMEOUT must be positive")
	}

	parsedUpstreams := make([]*url.URL, 0, len(upstreams))

	for _, rawUpstream := range upstreams {
		rawUpstream = strings.TrimSpace(rawUpstream)
		if rawUpstream == "" {
			continue
		}

		parsed, err := url.Parse(rawUpstream)
		if err != nil {
			return nil, fmt.Errorf("parse upstream %q: %w", rawUpstream, err)
		}

		if parsed.Scheme != "https" || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
			return nil, fmt.Errorf("invalid HTTPS upstream %q", rawUpstream)
		}

		parsed.Path = strings.TrimRight(parsed.Path, "/")
		parsedUpstreams = append(parsedUpstreams, parsed)
	}

	if len(parsedUpstreams) == 0 {
		return nil, errors.New("at least one upstream is required")
	}

	return &mirrorServer{
		cacheDir: cacheDir,
		cacheTTL: cacheTTL,
		client:   &http.Client{Timeout: requestTimeout},
		now:      time.Now,
		upstream: parsedUpstreams,
		inflight: map[string]*fetchCall{},
	}, nil
}

func (s *mirrorServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

			return
		}

		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = io.WriteString(w, "ok\n")
		}

		return
	}

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

		return
	}

	started := s.now()
	requestPath, err := validGNUPath(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)

		return
	}

	cachePath, err := s.cachePath(requestPath)
	if err != nil {
		http.Error(w, "invalid path", http.StatusBadRequest)

		return
	}

	cacheState := "HIT"
	upstream := ""
	info, statErr := os.Stat(cachePath)
	fresh := statErr == nil && info.Mode().IsRegular() && s.now().Sub(info.ModTime()) <= s.cacheTTL

	if !fresh {
		upstream, err = s.ensureCached(requestPath, cachePath)
		if err != nil {
			if statErr == nil && info.Mode().IsRegular() {
				cacheState = "STALE"
			} else {
				log.Printf("path=%q cache=ERROR error=%q duration=%q", requestPath, err, s.now().Sub(started))
				http.Error(w, "all upstreams failed", http.StatusBadGateway)

				return
			}
		} else {
			cacheState = "MISS"
		}
	}

	if upstream != "" {
		w.Header().Set("X-Upstream", upstream)
	}
	w.Header().Set("X-Cache", cacheState)

	if err = serveFile(w, r, cachePath); err != nil {
		log.Printf("path=%q cache=%s error=%q duration=%q", requestPath, cacheState, err, s.now().Sub(started))
		if !errors.Is(err, os.ErrNotExist) {
			return
		}

		http.Error(w, "cached file disappeared", http.StatusInternalServerError)

		return
	}

	log.Printf("path=%q cache=%s upstream=%q duration=%q", requestPath, cacheState, upstream, s.now().Sub(started))
}

func validGNUPath(r *http.Request) (string, error) {
	if r.URL.RawQuery != "" || r.URL.Fragment != "" {
		return "", errors.New("query and fragment are not allowed")
	}

	requestPath := r.URL.Path
	if !strings.HasPrefix(requestPath, "/gnu/") || requestPath == "/gnu/" || path.Clean(requestPath) != requestPath || strings.ContainsRune(requestPath, '\\') {
		return "", errors.New("path must be canonical and below /gnu/")
	}

	return requestPath, nil
}

func (s *mirrorServer) cachePath(requestPath string) (string, error) {
	cacheRoot, err := filepath.Abs(s.cacheDir)
	if err != nil {
		return "", err
	}

	candidate := filepath.Join(cacheRoot, filepath.FromSlash(strings.TrimPrefix(requestPath, "/")))
	relative, err := filepath.Rel(cacheRoot, candidate)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("path escapes cache")
	}

	return candidate, nil
}

func (s *mirrorServer) ensureCached(requestPath, cachePath string) (string, error) {
	s.mu.Lock()
	if existing := s.inflight[requestPath]; existing != nil {
		s.mu.Unlock()
		<-existing.done

		return existing.upstream, existing.err
	}

	call := &fetchCall{done: make(chan struct{})}
	s.inflight[requestPath] = call
	s.mu.Unlock()

	call.upstream, call.err = s.fetch(requestPath, cachePath)

	s.mu.Lock()
	delete(s.inflight, requestPath)
	close(call.done)
	s.mu.Unlock()

	return call.upstream, call.err
}

func (s *mirrorServer) fetch(requestPath, cachePath string) (string, error) {
	var failures []error

	for _, upstream := range s.upstream {
		fetchURL := *upstream
		fetchURL.Path = upstream.Path + requestPath

		request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, fetchURL.String(), nil)
		if err != nil {
			failures = append(failures, err)

			continue
		}

		response, err := s.client.Do(request)
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", upstream, err))

			continue
		}

		if response.StatusCode != http.StatusOK {
			_ = response.Body.Close()
			failures = append(failures, fmt.Errorf("%s: status %s", upstream, response.Status))

			continue
		}

		err = s.store(response.Body, cachePath)
		closeErr := response.Body.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", upstream, err))

			continue
		}

		return upstream.String(), nil
	}

	return "", errors.Join(failures...)
}

func (s *mirrorServer) store(source io.Reader, cachePath string) error {
	cacheDirectory := filepath.Dir(cachePath)
	if err := os.MkdirAll(cacheDirectory, 0o755); err != nil {
		return err
	}

	temporary, err := os.CreateTemp(cacheDirectory, ".download-*")
	if err != nil {
		return err
	}

	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)

	if _, err = io.Copy(temporary, source); err != nil {
		_ = temporary.Close()

		return err
	}

	if err = temporary.Sync(); err != nil {
		_ = temporary.Close()

		return err
	}

	if err = temporary.Close(); err != nil {
		return err
	}

	if err = os.Chtimes(temporaryPath, s.now(), s.now()); err != nil {
		return err
	}

	if err = os.Rename(temporaryPath, cachePath); err != nil {
		return err
	}

	directory, err := os.Open(cacheDirectory)
	if err != nil {
		return err
	}
	defer directory.Close()

	return directory.Sync()
}

func serveFile(w http.ResponseWriter, r *http.Request, filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}

	http.ServeContent(w, r, info.Name(), info.ModTime(), file)

	return nil
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}

	return fallback
}
