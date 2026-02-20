package mapper

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"

	"github.com/had-nu/sec-headers-check/internal/headers"
)

const (
	requestTimeout = 10 * time.Second
	userAgent      = "sec-headers-check/2.0.0"
)

// CommonPaths are common endpoints we check the existence of.
var CommonPaths = []string{
	"/", "/login", "/auth/login", "/me/settings", "/api/me/self",
	"/admin", "/api/v1/health", "/health", "/status", "/api",
}

// MapEndpoints discovers endpoints for a given targeted base URL
// using a hybrid approach (simple crawl + common path fuzzing).
func MapEndpoints(ctx context.Context, baseURL string, maxEndpoints int) []headers.Endpoint {
	client := &http.Client{Timeout: requestTimeout}

	discovered := make(map[string]bool)
	var mu sync.Mutex

	// 1. Helper function to check and add an endpoint if it exists
	checkAndAdd := func(path string, method string) {
		fullURL := strings.TrimRight(baseURL, "/") + path
		req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
		if err != nil {
			return
		}
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("Accept", "*/*")

		resp, err := client.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusForbidden {
			mu.Lock()
			discovered[path] = true
			mu.Unlock()
		}
	}

	// 2. Crawl the main page looking for links
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		crawlLinks(ctx, client, baseURL, &mu, discovered)
	}()

	// 3. Simultaneously check common paths
	for _, path := range CommonPaths {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			checkAndAdd(p, "GET")
		}(path)
	}

	wg.Wait()

	// 4. Convert to []headers.Endpoint
	var endpoints []headers.Endpoint
	for path := range discovered {
		if len(endpoints) >= maxEndpoints && maxEndpoints > 0 {
			break
		}
		endpoints = append(endpoints, headers.Endpoint{
			Path:   path,
			Method: "GET", // Most discovered endpoints are GET
		})
	}

	// Ensure we always have at least "/"
	if len(endpoints) == 0 {
		endpoints = append(endpoints, headers.Endpoint{Path: "/", Method: "GET"})
	}

	return endpoints
}

func crawlLinks(ctx context.Context, client *http.Client, baseURL string, mu *sync.Mutex, discovered map[string]bool) {
	req, err := http.NewRequestWithContext(ctx, "GET", baseURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	parsedBase, err := url.Parse(baseURL)
	if err != nil {
		return
	}

	z := html.NewTokenizer(resp.Body)
	for {
		if ctx.Err() != nil {
			break // context cancelled
		}
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt == html.StartTagToken {
			t := z.Token()
			if t.Data == "a" {
				for _, a := range t.Attr {
					if a.Key == "href" {
						processHref(a.Val, parsedBase, mu, discovered)
						break
					}
				}
			}
		}
	}
}

func processHref(href string, parsedBase *url.URL, mu *sync.Mutex, discovered map[string]bool) {
	href = strings.TrimSpace(href)
	if href == "" || strings.HasPrefix(href, "#") || strings.HasPrefix(href, "javascript:") || strings.HasPrefix(href, "mailto:") {
		return
	}

	parsedHref, err := url.Parse(href)
	if err != nil {
		return
	}

	// Resolve relative URLs
	resolved := parsedBase.ResolveReference(parsedHref)

	// Filter out external links by comparing hosts
	if resolved.Host != parsedBase.Host {
		return
	}

	path := resolved.Path
	if path == "" {
		path = "/"
	}
	// Normalise path
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	mu.Lock()
	discovered[path] = true
	mu.Unlock()
}
