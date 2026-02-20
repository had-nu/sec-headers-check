package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strings"

	"github.com/had-nu/sec-headers-check/internal/checker"
	"github.com/had-nu/sec-headers-check/internal/headers"
	"github.com/had-nu/sec-headers-check/internal/output"
)

const version = "2.0.0"

// domainRegex is compiled once at package level; recompiling on every call is wasteful.
var domainRegex = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

// ANSI colour codes used only in main for the banner and validation messages.
const (
	colorReset      = "\033[0m"
	colorPurple     = "\033[35m"
	colorPurpleBold = "\033[1;35m"
	colorPurpleDim  = "\033[2;35m"
	colorBlue       = "\033[34m"
	colorCyan       = "\033[36m"
	colorRed        = "\033[31m"
	colorBold       = "\033[1m"
	colorDim        = "\033[2m"
	colorYellow     = "\033[33m"
)

func displayBanner() {
	fmt.Println(colorPurpleBold + `
  ·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·`)
	fmt.Println(colorPurpleDim + `
  ░ ░ ▓ ░ submersion protocol active ░ headers exposed ░ trust eroding ░ ▓ ░ ░`)
	fmt.Println(colorPurpleBold + `
  ███╗   ███╗ █████╗ ███████╗████████╗██╗  ██╗███████╗ █████╗ ██████╗
  ████╗ ████║██╔══██╗██╔════╝╚══██╔══╝██║  ██║██╔════╝██╔══██╗██╔══██╗
  ██╔████╔██║███████║███████╗   ██║   ███████║█████╗  ███████║██║  ██║
  ██║╚██╔╝██║██╔══██║╚════██║   ██║   ██╔══██║██╔══╝  ██╔══██║██║  ██║
  ██║ ╚═╝ ██║██║  ██║███████║   ██║   ██║  ██║███████╗██║  ██║██████╔╝
  ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ` + colorReset)
	fmt.Println(colorPurple + "                  security headers drift down into the abyss — we surface them" + colorReset)
	fmt.Println(colorPurpleDim + "                                              v" + version + colorReset)
	fmt.Println(colorPurpleBold + `
  ·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·:·` + colorReset)
	fmt.Println()
}

func isValidDomain(s string) bool { return domainRegex.MatchString(s) }
func isValidIP(s string) bool     { return net.ParseIP(s) != nil }
func isValidURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

// normaliseTarget ensures the target carries an http/https scheme.
func normaliseTarget(target string) (string, bool) {
	switch {
	case isValidURL(target):
		return target, true
	case isValidDomain(target):
		return "https://" + target, true
	case isValidIP(target):
		return "https://" + target, true
	default:
		return "", false
	}
}

func main() {
	// ── CLI flags ─────────────────────────────────────────────────────────────
	targetFlag := flag.String("target", "", "Domain, IP or full URL to scan")
	formatFlag := flag.String("output", "terminal", "Output format: terminal | json | csv")
	outFileFlag := flag.String("out", "", "Write output to file instead of stdout (optional)")
	flag.Parse()

	displayBanner()

	// ── Resolve target ────────────────────────────────────────────────────────
	target := strings.TrimSpace(*targetFlag)

	if target == "" {
		// Interactive fallback when -target is not provided.
		paths := make([]string, len(headers.Endpoints))
		for i, ep := range headers.Endpoints {
			paths[i] = ep.Path
		}
		fmt.Println("\nDigite o domínio base a ser verificado (ex: exemplo.com):")
		fmt.Printf("%sEndpoints: %s%s\n", colorBlue, strings.Join(paths, ", "), colorReset)
		fmt.Print(colorCyan + "> " + colorReset)

		reader := bufio.NewReader(os.Stdin)
		line, err := reader.ReadString('\n')
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s[✗] Erro ao ler input: %v%s\n", colorRed, err, colorReset)
			os.Exit(1)
		}
		target = strings.TrimSpace(line)
	}

	if target == "" {
		fmt.Fprintf(os.Stderr, "%s[✗] Alvo não especificado.%s\n", colorRed, colorReset)
		os.Exit(1)
	}

	normalisedTarget, ok := normaliseTarget(target)
	if !ok {
		fmt.Fprintf(os.Stderr, "%s[✗] Formato inválido: %q. Use um domínio, IP ou URL.%s\n",
			colorRed, target, colorReset)
		os.Exit(1)
	}

	if normalisedTarget != target {
		fmt.Printf("%s[*] Protocolo adicionado: %s%s\n\n", colorYellow, normalisedTarget, colorReset)
	}

	// ── Resolve output writer ─────────────────────────────────────────────────
	writer := os.Stdout
	if *outFileFlag != "" {
		f, err := os.Create(*outFileFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s[✗] Não foi possível criar arquivo de saída: %v%s\n",
				colorRed, err, colorReset)
			os.Exit(1)
		}
		defer f.Close()
		writer = f
		fmt.Printf("%s[*] Escrevendo saída em: %s%s\n\n", colorCyan, *outFileFlag, colorReset)
	}

	// ── Signal-aware context ──────────────────────────────────────────────────
	// signal.NotifyContext cancels ctx on SIGINT/SIGTERM, propagating cancellation to all in-flight HTTP requests instead of waiting for individual timeouts.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// ── Run scan ──────────────────────────────────────────────────────────────
	fmt.Printf("%s[*] Iniciando verificação concorrente (%d endpoints)...%s\n\n",
		colorCyan, len(headers.Endpoints), colorReset)

	rawResults := checker.CheckAll(ctx, normalisedTarget)
	report := output.Build(normalisedTarget, rawResults)

	// ── Emit output ───────────────────────────────────────────────────────────
	var writeErr error
	switch *formatFlag {
	case "json":
		writeErr = output.WriteJSON(writer, report)
	case "csv":
		writeErr = output.WriteCSV(writer, report)
	default: // "terminal" or unrecognised — fall back to coloured terminal output
		if *formatFlag != "terminal" {
			fmt.Fprintf(os.Stderr, "%s[!] Formato desconhecido %q — usando terminal.%s\n",
				colorYellow, *formatFlag, colorReset)
		}
		output.PrintTerminal(writer, report)
	}

	if writeErr != nil {
		fmt.Fprintf(os.Stderr, "%s[✗] Erro ao escrever output: %v%s\n", colorRed, writeErr, colorReset)
		os.Exit(1)
	}

	if *outFileFlag == "" && *formatFlag == "terminal" {
		fmt.Printf("\n%s[*] Verificação concluída. Pressione Enter para sair...%s\n", colorCyan, colorReset)
		bufio.NewReader(os.Stdin).ReadString('\n') //nolint:errcheck // interactive pause; error irrelevant
	}
}