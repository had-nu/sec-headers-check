package output

import (
	"time"

	"github.com/had-nu/sec-headers-check/internal/checker"
	"github.com/had-nu/sec-headers-check/internal/headers"
)

// HeaderResult is the evaluated state of one security header for one endpoint.
type HeaderResult struct {
	Name     string `json:"name"`
	Present  bool   `json:"present"`
	Value    string `json:"value,omitempty"`
	Severity string `json:"severity"`
	Points   int    `json:"points"`
}

// EndpointReport is the processed, format-agnostic result for one endpoint.
type EndpointReport struct {
	Path       string         `json:"path"`
	Method     string         `json:"method"`
	StatusCode int            `json:"status_code,omitempty"`
	Score      int            `json:"score"`
	Error      string         `json:"error,omitempty"`
	Headers    []HeaderResult `json:"headers,omitempty"`
}

type Report struct {
	Target              string           `json:"target"`
	GeneratedAt         time.Time        `json:"generated_at"`
	Endpoints           []EndpointReport `json:"endpoints"`
	AverageScore        int              `json:"average_score"`
	InconsistentHeaders []string         `json:"inconsistent_headers"`
}

func Build(target string, results []checker.EndpointResult) Report {
	eps := make([]EndpointReport, 0, len(results))
	totalScore, validCount := 0, 0

	for _, r := range results {
		ep := EndpointReport{
			Path:   r.Path,
			Method: r.Method,
		}

		if r.Error != nil {
			ep.Error = r.Error.Error()
		} else {
			ep.StatusCode = r.StatusCode
			ep.Score = r.Score
			totalScore += r.Score
			validCount++
			ep.Headers = buildHeaderResults(r)
		}

		eps = append(eps, ep)
	}

	avg := 0
	if validCount > 0 {
		avg = totalScore / validCount
	}

	return Report{
		Target:              target,
		GeneratedAt:         time.Now().UTC(),
		Endpoints:           eps,
		AverageScore:        avg,
		InconsistentHeaders: findInconsistencies(eps),
	}
}

func buildHeaderResults(r checker.EndpointResult) []HeaderResult {
	hrs := make([]HeaderResult, len(headers.SecurityHeaders))
	for i, sh := range headers.SecurityHeaders {
		val := r.Headers.Get(sh.Name)
		hrs[i] = HeaderResult{
			Name:     sh.Name,
			Present:  val != "",
			Value:    val,
			Severity: sh.Severity,
			Points:   sh.Points,
		}
	}
	return hrs
}

func findInconsistencies(eps []EndpointReport) []string {
	valid := make([]EndpointReport, 0, len(eps))
	for _, ep := range eps {
		if ep.Error == "" {
			valid = append(valid, ep)
		}
	}
	if len(valid) < 2 {
		return nil
	}

	var inconsistent []string
	for _, sh := range headers.SecurityHeaders {
		first := headerPresent(valid[0], sh.Name)
		for _, ep := range valid[1:] {
			if headerPresent(ep, sh.Name) != first {
				inconsistent = append(inconsistent, sh.Name)
				break
			}
		}
	}
	return inconsistent
}

func headerPresent(ep EndpointReport, name string) bool {
	for _, h := range ep.Headers {
		if h.Name == name {
			return h.Present
		}
	}
	return false
}