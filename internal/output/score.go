package output

import (
	"net/http"

	"github.com/had-nu/sec-headers-check/internal/headers"
)

// The score is proportional to the sum of Points for each present header divided by headers.MaxPossibleScore.
func ScoreHeaders(h http.Header) int {
	if headers.MaxPossibleScore == 0 {
		return 0
	}

	score := 0
	for _, sh := range headers.SecurityHeaders {
		if h.Get(sh.Name) != "" {
			score += sh.Points
		}
	}

	return int(float64(score) / float64(headers.MaxPossibleScore) * 100)
}