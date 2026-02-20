package output

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
)

// csvColumns defines the column order for every CSV row.
var csvColumns = []string{
	"target",
	"generated_at",
	"path",
	"method",
	"status_code",
	"endpoint_score",
	"header_name",
	"present",
	"value",
	"severity",
	"points",
}

// WriteCSV writes the Report as a flat CSV to w.
func WriteCSV(w io.Writer, r Report) error {
	cw := csv.NewWriter(w)

	if err := cw.Write(csvColumns); err != nil {
		return fmt.Errorf("csv write header: %w", err)
	}

	generatedAt := r.GeneratedAt.Format("2006-01-02T15:04:05Z")

	for _, ep := range r.Endpoints {
		if ep.Error != "" {
			// One row per failed endpoint; header columns are left blank.
			row := []string{
				r.Target, generatedAt,
				ep.Path, ep.Method,
				"", // status_code
				"", // endpoint_score
				"", // header_name
				"", // present
				ep.Error, // value column carries the error message
				"", // severity
				"", // points
			}
			if err := cw.Write(row); err != nil {
				return fmt.Errorf("csv write error row: %w", err)
			}
			continue
		}

		for _, h := range ep.Headers {
			row := []string{
				r.Target,
				generatedAt,
				ep.Path,
				ep.Method,
				strconv.Itoa(ep.StatusCode),
				strconv.Itoa(ep.Score),
				h.Name,
				strconv.FormatBool(h.Present),
				h.Value,
				h.Severity,
				strconv.Itoa(h.Points),
			}
			if err := cw.Write(row); err != nil {
				return fmt.Errorf("csv write row: %w", err)
			}
		}
	}

	cw.Flush()
	return cw.Error()
}