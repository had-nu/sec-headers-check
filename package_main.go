package main

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
	"regexp"
	"net"
)

const version = "1.1.0-multi-endpoint"

// Estrutura para descrever cabeçalhos de segurança
type SecurityHeader struct {
	Name        string
	Description string
	Expected    string
	Severity    string // Critical, High, Medium, Low
}

// Estrutura para armazenar resultados de um endpoint
type EndpointResult struct {
	Path        string
	StatusCode  int
	Headers     http.Header
	Score       int
	Error       error
}

// Lista de endpoints para verificar
var endpoints = []string{
	"/",
	"/login",
	"/auth/login",
	"/me/settings",
	"/api/me/self",
}

// Lista de cabeçalhos críticos de segurança
var securityHeaders = []SecurityHeader{
    {
        Name:        "Strict-Transport-Security",
        Description: "Força conexões HTTPS e previne downgrade attacks",
        Expected:    "max-age=31536000; includeSubDomains",
        Severity:    "Critical",
    },
    {
        Name:        "Content-Security-Policy", 
        Description: "Previne XSS, injection e data exfiltration",
        Expected:    "default-src 'self'; script-src 'self'",
        Severity:    "Critical",
    },
    {
        Name:        "X-Frame-Options",
        Description: "Previne clickjacking e UI redressing",
        Expected:    "DENY",
        Severity:    "High",
    },
    {
        Name:        "X-Content-Type-Options",
        Description: "Previne MIME sniffing attacks",
        Expected:    "nosniff", 
        Severity:    "High",
    },
    {
        Name:        "Referrer-Policy",
        Description: "Controla vazamento de informações via referrer",
        Expected:    "strict-origin-when-cross-origin",
        Severity:    "Medium",
    },
    {
        Name:        "Cache-Control",
        Description: "Previne cache de dados sensitivos",
        Expected:    "no-store, no-cache, must-revalidate",
        Severity:    "Medium", // Para páginas com dados sensíveis
    },
    {
        Name:        "X-XSS-Protection",
        Description: "Browser XSS filter (legacy, mas ainda relevante)",
        Expected:    "1; mode=block",
        Severity:    "Low", // Legado, CSP é mais efetivo
    },
    {
        Name:        "Server",
        Description: "Information disclosure via server banner",
        Expected:    "não presente ou valor genérico",
        Severity:    "Low",
    },
}

// Cores ANSI para output colorido
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
	colorBold   = "\033[1m"
)

// Função para exibir o banner da aplicação
func displayBanner() {
	fmt.Println(colorYellow + colorBold + `
 ███████╗███████╗ ██████╗      ██╗  ██╗███████╗ █████╗ ██████╗ ███████╗██████╗ ███████╗
 ██╔════╝██╔════╝██╔════╝      ██║  ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝
 ███████╗█████╗  ██║     █████╗███████║█████╗  ███████║██║  ██║█████╗  ██████╔╝███████╗
 ╚════██║██╔══╝  ██║     ╚════╝██╔══██║██╔══╝  ██╔══██║██║  ██║██╔══╝  ██╔══██╗╚════██║
 ███████║███████╗╚██████╗      ██║  ██║███████╗██║  ██║██████╔╝███████╗██║  ██║███████║
 ╚══════╝╚══════╝ ╚═════╝      ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝` + colorReset)
	fmt.Println(colorYellow + colorBold + "              Security Headers Checker v" + version + colorReset)
	fmt.Println(colorCyan + "════════════════════════════════════════════════════════════════════════════════════════" + colorReset)
}

// Valida se uma entrada é um domínio válido
func isValidDomain(domain string) bool {
	pattern := `^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`
	match, _ := regexp.MatchString(pattern, domain)
	return match
}

// Valida se uma entrada é um endereço IP válido
func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// Verifica se a entrada é um URL válido (com protocolo)
func isValidURL(url string) bool {
	return strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://")
}

// Faz requisição para um endpoint específico
func checkEndpoint(baseURL, endpoint string) EndpointResult {
	fullURL := strings.TrimRight(baseURL, "/") + endpoint
	
	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Permitir até 3 redirecionamentos
			if len(via) >= 3 {
				return fmt.Errorf("muitos redirecionamentos")
			}
			return nil
		},
	}

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return EndpointResult{
			Path:  endpoint,
			Error: err,
		}
	}

	// Simula um navegador para obter respostas mais realistas
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	resp, err := client.Do(req)
	if err != nil {
		return EndpointResult{
			Path:  endpoint,
			Error: err,
		}
	}
	defer resp.Body.Close()

	score := calculateSecurityScore(resp.Header)

	return EndpointResult{
		Path:       endpoint,
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Score:      score,
		Error:      nil,
	}
}

// Função principal para verificar cabeçalhos em múltiplos endpoints
func checkHeaders(target string) {
	// Determinar protocolo se não for especificado
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
		fmt.Printf("%sProtocolo não especificado. Usando: %s%s\n\n", colorYellow, target, colorReset)
	}

	fmt.Printf("%s[*] Verificando cabeçalhos em múltiplos endpoints...%s\n", colorCyan, colorReset)
	fmt.Printf("%s[*] Alvo: %s%s\n\n", colorCyan, target, colorReset)

	// Coletar resultados de todos os endpoints
	var results []EndpointResult
	
	for _, endpoint := range endpoints {
		fmt.Printf("%s[*] Verificando %s%s%s... ", colorBlue, target+endpoint, colorReset, "")
		result := checkEndpoint(target, endpoint)
		results = append(results, result)
		
		if result.Error != nil {
			fmt.Printf("%s[✗] Erro: %s%s\n", colorRed, result.Error, colorReset)
		} else {
			fmt.Printf("%s[✓] HTTP %d%s\n", colorGreen, result.StatusCode, colorReset)
		}
	}

	fmt.Println()

	// Analisar e exibir resultados para cada endpoint
	for _, result := range results {
		if result.Error != nil {
			continue
		}

		fmt.Printf("%s[*] Análise detalhada: %s%s%s\n", colorCyan, colorBold, result.Path, colorReset)
		fmt.Printf("%s[*] URL completa: %s%s\n", colorBlue, target+result.Path, colorReset)
		fmt.Printf("%s[*] Status: HTTP %d%s\n", colorBlue, result.StatusCode, colorReset)
		fmt.Printf("%s%s%s\n", colorCyan, strings.Repeat("═", 100), colorReset)

		// DEBUG: Mostrar todos os cabeçalhos recebidos
		fmt.Printf("%s[DEBUG] Todos os cabeçalhos recebidos:%s\n", colorYellow, colorReset)
		for name, values := range result.Headers {
			fmt.Printf("  %s: %s\n", name, strings.Join(values, ", "))
		}
		fmt.Printf("%s%s%s\n", colorYellow, strings.Repeat("─", 50), colorReset)

		// Contadores para resumo
		var present, missing, total int
		total = len(securityHeaders)

		// Imprimir cabeçalho da tabela
		fmt.Printf("%-35s %-15s %-10s %s\n", "CABEÇALHO", "ESTADO", "SEVERIDADE", "VALOR")
		fmt.Printf("%s%s%s\n", colorCyan, strings.Repeat("─", 100), colorReset)

		// Verificar cada cabeçalho de segurança
		for _, header := range securityHeaders {
			headerValue := result.Headers.Get(header.Name)
			
			if headerValue != "" {
				present++
				fmt.Printf("%-35s %s%-15s%s %s%-10s%s %s\n", 
					header.Name, 
					colorGreen, "PRESENTE", colorReset,
					getSeverityColor(header.Severity), header.Severity, colorReset,
					truncateString(headerValue, 40))
			} else {
				missing++
				fmt.Printf("%-35s %s%-15s%s %s%-10s%s %s\n", 
					header.Name, 
					colorRed, "AUSENTE", colorReset,
					getSeverityColor(header.Severity), header.Severity, colorReset,
					"-")
			}
		}

		// Resumo do endpoint
		fmt.Printf("\n%s[*] Resumo %s:%s\n", colorCyan, result.Path, colorReset)
		fmt.Printf("Cabeçalhos presentes: %s%d/%d (%.1f%%)%s\n", 
			colorGreen, present, total, float64(present)/float64(total)*100, colorReset)
		fmt.Printf("Pontuação: %s%d/100%s %s\n\n", 
			getScoreColor(result.Score), result.Score, colorReset, getScoreEmoji(result.Score))
	}

	// Resumo geral
	displayOverallSummary(results)
}

// Exibe um resumo geral de todos os endpoints
func displayOverallSummary(results []EndpointResult) {
	fmt.Printf("%s[*] RESUMO GERAL%s\n", colorCyan+colorBold, colorReset)
	fmt.Printf("%s%s%s\n", colorCyan, strings.Repeat("═", 100), colorReset)

	totalScore := 0
	validEndpoints := 0
	
	// Tabela de scores por endpoint
	fmt.Printf("%-20s %-12s %-12s %s\n", "ENDPOINT", "STATUS", "SCORE", "AVALIAÇÃO")
	fmt.Printf("%s%s%s\n", colorCyan, strings.Repeat("─", 100), colorReset)
	
	for _, result := range results {
		if result.Error != nil {
			fmt.Printf("%-20s %s%-12s%s %-12s %s\n", 
				result.Path, colorRed, "ERRO", colorReset, "-", "Falha na conexão")
		} else {
			validEndpoints++
			totalScore += result.Score
			fmt.Printf("%-20s %s%-12s%s %s%-12d%s %s\n", 
				result.Path, 
				getStatusColor(result.StatusCode), fmt.Sprintf("HTTP %d", result.StatusCode), colorReset,
				getScoreColor(result.Score), result.Score, colorReset,
				getScoreEmoji(result.Score))
		}
	}

	if validEndpoints > 0 {
		avgScore := totalScore / validEndpoints
		fmt.Printf("\n%s[*] Pontuação média: %s%d/100%s %s%s\n", 
			colorCyan, getScoreColor(avgScore), avgScore, colorReset, getScoreEmoji(avgScore), colorReset)
	}

	// Análise de consistência
	fmt.Printf("\n%s[*] Análise de consistência:%s\n", colorCyan, colorReset)
	analyzeConsistency(results)
}

// Analisa a consistência dos cabeçalhos entre endpoints
func analyzeConsistency(results []EndpointResult) {
	headerPresence := make(map[string][]bool)
	
	// Coletar presença de cada cabeçalho em cada endpoint
	for _, header := range securityHeaders {
		for _, result := range results {
			if result.Error == nil {
				hasHeader := result.Headers.Get(header.Name) != ""
				headerPresence[header.Name] = append(headerPresence[header.Name], hasHeader)
			}
		}
	}

	// Identificar inconsistências
	inconsistentHeaders := []string{}
	for headerName, presence := range headerPresence {
		if len(presence) > 1 {
			first := presence[0]
			consistent := true
			for _, p := range presence[1:] {
				if p != first {
					consistent = false
					break
				}
			}
			if !consistent {
				inconsistentHeaders = append(inconsistentHeaders, headerName)
			}
		}
	}

	if len(inconsistentHeaders) > 0 {
		fmt.Printf("%s[!]  Cabeçalhos inconsistentes encontrados:%s\n", colorYellow, colorReset)
		for _, header := range inconsistentHeaders {
			fmt.Printf("   • %s\n", header)
		}
		fmt.Printf("%sRecomendação: Verificar configuração do servidor para garantir consistência.%s\n", 
			colorYellow, colorReset)
	} else {
		fmt.Printf("%s✓ Configurações consistentes entre todos os endpoints.%s\n", 
			colorGreen, colorReset)
	}
}

// Trunca string para exibição
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// Retorna cor baseada no status HTTP
func getStatusColor(status int) string {
	switch {
	case status >= 200 && status < 300:
		return colorGreen
	case status >= 300 && status < 400:
		return colorYellow
	case status >= 400:
		return colorRed
	default:
		return colorReset
	}
}

// Retorna a cor associada à severidade
func getSeverityColor(severity string) string {
	switch severity {
	case "Critical":
		return colorRed + colorBold
	case "High":
		return colorRed
	case "Medium":
		return colorYellow
	case "Low":
		return colorGreen
	default:
		return colorReset
	}
}

// Calcula uma pontuação de segurança baseada nos cabeçalhos
func calculateSecurityScore(headers http.Header) int {
	score := 0
	maxScore := 0
	
	for _, header := range securityHeaders {
		var headerPoints int
		
		switch header.Severity {
		case "Critical":
			headerPoints = 20
		case "High":
			headerPoints = 15
		case "Medium":
			headerPoints = 10
		case "Low":
			headerPoints = 5
		}
		
		maxScore += headerPoints
		
		if headerValue := headers.Get(header.Name); headerValue != "" {
			if header.Name == "Strict-Transport-Security" && strings.Contains(headerValue, "max-age=") {
				score += headerPoints
			} else if header.Name == "Content-Security-Policy" && len(headerValue) > 10 {
				score += headerPoints
			} else {
				score += headerPoints
			}
		}
	}
	
	// Normaliza para 100 pontos
	if maxScore > 0 {
		return int((float64(score) / float64(maxScore)) * 100)
	}
	
	return 0
}

// Retorna a cor baseada na pontuação
func getScoreColor(score int) string {
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

// Retorna um emoji baseado na pontuação
func getScoreEmoji(score int) string {
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

func main() {
	displayBanner()
	
	reader := bufio.NewReader(os.Stdin)
	
	fmt.Println("\nDigite o domínio base a ser verificado (ex: exemplo.com):")
	fmt.Printf("%sEndpoints que serão verificados: %s%s\n", colorBlue, strings.Join(endpoints, ", "), colorReset)
	fmt.Print(colorCyan + "> " + colorReset)
	
	target, _ := reader.ReadString('\n')
	target = strings.TrimSpace(target)
	
	if target == "" {
		fmt.Printf("%s[✗] Alvo não especificado.%s\n", colorRed, colorReset)
		return
	}
	
	// Validar a entrada
	if isValidURL(target) {
		fmt.Printf("%s[*] Formato detectado: URL completa%s\n", colorBlue, colorReset)
	} else if isValidDomain(target) {
		fmt.Printf("%s[*] Formato detectado: Domínio%s\n", colorBlue, colorReset)
	} else if isValidIP(target) {
		fmt.Printf("%s[*] Formato detectado: Endereço IP%s\n", colorBlue, colorReset)
	} else {
		fmt.Printf("%s[✗] Formato inválido. Por favor, insira um domínio, IP ou URL válida.%s\n", colorRed, colorReset)
		return
	}
	
	fmt.Println()
	checkHeaders(target)
	
	fmt.Printf("\n%s[*] Verificação concluída! Pressione Enter para sair...%s\n", colorCyan, colorReset)
	reader.ReadString('\n')
}