package checker

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/had-nu/sec-headers-check/internal/headers"
)

const (
	requestTimeout = 15 * time.Second
	maxRedirects   = 3
	userAgent      = "sec-headers-check/2.0.0"
)

type EndpointResult struct {
	Path       string
	Method     string
	StatusCode int
	Headers    http.Header
	Score      int
	Error      error
}

func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: requestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("exceeded %d redirects", maxRedirects)
			}
			return nil
		},
	}
}

func checkEndpoint(ctx context.Context, client *http.Client, baseURL string, ep headers.Endpoint) EndpointResult {
	fullURL := strings.TrimRight(baseURL, "/") + ep.Path

	req, err := http.NewRequestWithContext(ctx, ep.Method, fullURL, nil)
	if err != nil {
		return EndpointResult{
			Path:   ep.Path,
			Method: ep.Method,
			Error:  fmt.Errorf("build request: %w", err),
		}
	}

	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Connection", "keep-alive")

	resp, err := client.Do(req)
	if err != nil {
		return EndpointResult{
			Path:   ep.Path,
			Method: ep.Method,
			Error:  fmt.Errorf("do request: %w", err),
		}
	}
	defer resp.Body.Close()

	return EndpointResult{
		Path:       ep.Path,
		Method:     ep.Method,
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		// Score:      ScoreHeaders(resp.Header),
	}
}

func CheckAll(ctx context.Context, baseURL string) []EndpointResult {
	client := newHTTPClient()

	resultsCh := make(chan EndpointResult, len(headers.Endpoints))

	var wg sync.WaitGroup
	for _, ep := range headers.Endpoints {
		wg.Add(1)
		go func(ep headers.Endpoint) {
			defer wg.Done()
			resultsCh <- checkEndpoint(ctx, client, baseURL, ep)
		}(ep)
	}

	// Close channel once all workers are done so the range below terminates.
	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	results := make([]EndpointResult, 0, len(headers.Endpoints))
	for r := range resultsCh {
		results = append(results, r)
	}

	// Sort by path for deterministic, reproducible output regardless of goroutine scheduling.
	sort.Slice(results, func(i, j int) bool {
		return results[i].Path < results[j].Path
	})

	return results
}
