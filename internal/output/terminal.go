package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/had-nu/sec-headers-check/internal/headers"
)

// ANSI colour codes. Kept package-private; only terminal.go uses them.
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
)

// PrintTerminal writes a human-readable, coloured report to w.
func PrintTerminal(w io.Writer, r Report) {
	fmt.Fprintf(w, "%s[*] Alvo: %s%s\n", colorCyan, r.Target, colorReset)
	fmt.Fprintf(w, "%s[*] Gerado em: %s%s\n\n",
		colorCyan, r.GeneratedAt.Format("2006-01-02 15:04:05 UTC"), colorReset)

	// Progress summary: one line per endpoint before the detailed breakdown.
	for _, ep := range r.Endpoints {
		if ep.Error != "" {
			fmt.Fprintf(w, "%s[✗] %-20s Erro: %s%s\n", colorRed, ep.Path, ep.Error, colorReset)
		} else {
			fmt.Fprintf(w, "%s[✓] %-20s HTTP %d%s\n", colorGreen, ep.Path, ep.StatusCode, colorReset)
		}
	}
	fmt.Fprintln(w)

	// Detailed per-endpoint table.
	for _, ep := range r.Endpoints {
		if ep.Error == "" {
			printEndpointDetail(w, ep)
		}
	}

	printOverallSummary(w, r)
	printConsistencyMatrix(w, r)
}

func printEndpointDetail(w io.Writer, ep EndpointReport) {
	fmt.Fprintf(w, "\n%s[*] Análise: %s%s%s\n", colorCyan, colorBold, ep.Path, colorReset)
	fmt.Fprintf(w, "%s[*] Método: %s | Status: HTTP %d%s\n",
		colorBlue, ep.Method, ep.StatusCode, colorReset)
	fmt.Fprintf(w, "%s%s%s\n", colorCyan, strings.Repeat("═", 100), colorReset)

	fmt.Fprintf(w, "%-35s %-15s %-10s %s\n", "CABEÇALHO", "ESTADO", "SEVERIDADE", "VALOR")
	fmt.Fprintf(w, "%s%s%s\n", colorCyan, strings.Repeat("─", 100), colorReset)

	present, total := 0, len(ep.Headers)
	for _, h := range ep.Headers {
		if h.Present {
			present++
			fmt.Fprintf(w, "%-35s %s%-15s%s %s%-10s%s %s\n",
				h.Name,
				colorGreen, "PRESENTE", colorReset,
				severityColor(h.Severity), h.Severity, colorReset,
				truncate(h.Value, 40))
		} else {
			fmt.Fprintf(w, "%-35s %s%-15s%s %s%-10s%s %s\n",
				h.Name,
				colorRed, "AUSENTE", colorReset,
				severityColor(h.Severity), h.Severity, colorReset,
				"-")
		}
	}

	if total > 0 {
		fmt.Fprintf(w, "\nCabeçalhos presentes: %s%d/%d (%.1f%%)%s\n",
			colorGreen, present, total, float64(present)/float64(total)*100, colorReset)
	}
	fmt.Fprintf(w, "Pontuação: %s%d/100%s %s\n",
		scoreColor(ep.Score), ep.Score, colorReset, scoreLabel(ep.Score))
}

func printOverallSummary(w io.Writer, r Report) {
	fmt.Fprintf(w, "\n%s%s[*] RESUMO GERAL%s\n", colorCyan, colorBold, colorReset)
	fmt.Fprintf(w, "%s%s%s\n", colorCyan, strings.Repeat("═", 100), colorReset)
	fmt.Fprintf(w, "%-20s %-12s %-12s %s\n", "ENDPOINT", "STATUS", "SCORE", "AVALIAÇÃO")
	fmt.Fprintf(w, "%s%s%s\n", colorCyan, strings.Repeat("─", 100), colorReset)

	for _, ep := range r.Endpoints {
		if ep.Error != "" {
			fmt.Fprintf(w, "%-20s %s%-12s%s %-12s %s\n",
				ep.Path, colorRed, "ERRO", colorReset, "-", ep.Error)
		} else {
			fmt.Fprintf(w, "%-20s %s%-12s%s %s%-12d%s %s\n",
				ep.Path,
				statusColor(ep.StatusCode), fmt.Sprintf("HTTP %d", ep.StatusCode), colorReset,
				scoreColor(ep.Score), ep.Score, colorReset,
				scoreLabel(ep.Score))
		}
	}

	fmt.Fprintf(w, "\n%s[*] Pontuação média: %s%d/100%s %s\n",
		colorCyan, scoreColor(r.AverageScore), r.AverageScore, colorReset, scoreLabel(r.AverageScore))
}

func printConsistencyMatrix(w io.Writer, r Report) {
	// Only include endpoints that succeeded.
	valid := make([]EndpointReport, 0, len(r.Endpoints))
	for _, ep := range r.Endpoints {
		if ep.Error == "" {
			valid = append(valid, ep)
		}
	}
	if len(valid) == 0 {
		return
	}

	fmt.Fprintf(w, "\n%s[+] Tabela de consistência:%s\n", colorCyan, colorReset)
	fmt.Fprintf(w, "%-35s", "CABEÇALHO")
	for _, ep := range valid {
		fmt.Fprintf(w, " %-15s", ep.Path)
	}
	fmt.Fprintf(w, "\n%s%s%s\n", colorCyan, strings.Repeat("─", 100), colorReset)

	// Iterate over SecurityHeaders (not over the map) to guarantee column order.
	for _, sh := range headers.SecurityHeaders {
		fmt.Fprintf(w, "%-35s", sh.Name)
		for _, ep := range valid {
			if headerPresent(ep, sh.Name) {
				fmt.Fprintf(w, " %s%-15s%s", colorGreen, "PRESENTE", colorReset)
			} else {
				fmt.Fprintf(w, " %s%-15s%s", colorRed, "AUSENTE", colorReset)
			}
		}
		fmt.Fprintln(w)
	}

	if len(r.InconsistentHeaders) > 0 {
		fmt.Fprintf(w, "\n%s[!] Cabeçalhos inconsistentes entre endpoints:%s\n", colorYellow, colorReset)
		for _, name := range r.InconsistentHeaders {
			fmt.Fprintf(w, "   • %s\n", name)
		}
		fmt.Fprintf(w, "%sRecomendação: aplicar cabeçalhos uniformemente em todas as rotas.%s\n",
			colorYellow, colorReset)
	} else {
		fmt.Fprintf(w, "%s✓ Cabeçalhos consistentes em todos os endpoints.%s\n", colorGreen, colorReset)
	}
}

// ── colour helpers ─────────────────────────────────────────────────────────────

func severityColor(s string) string {
	switch s {
	case "Critical":
		return colorRed + colorBold
	case "High":
		return colorRed
	case "Medium":
		return colorYellow
	default:
		return colorGreen
	}
}

func scoreColor(score int) string {
	switch {
	case score >= 90:
		return colorGreen + colorBold
	case score >= 70:
		return colorGreen
	case score >= 50:
		return colorYellow
	default:
		return colorRed
	}
}

func scoreLabel(score int) string {
	switch {
	case score >= 90:
		return "[✓] Excelente!"
	case score >= 70:
		return "[✓] Bom"
	case score >= 50:
		return "[!] Regular"
	case score >= 30:
		return "[!] Insuficiente"
	default:
		return "[✗] Crítico"
	}
}

func statusColor(status int) string {
	switch {
	case status >= 200 && status < 300:
		return colorGreen
	case status >= 300 && status < 400:
		return colorYellow
	default:
		return colorRed
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}