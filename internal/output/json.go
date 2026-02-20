package output

import (
	"encoding/json"
	"fmt"
	"io"
)

// WriteJSON serialises the Report as indented JSON and writes it to w.
func WriteJSON(w io.Writer, r Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("json encode: %w", err)
	}
	return nil
}