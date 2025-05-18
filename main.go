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

const version = "1.0.0-demo"

// Estrutura para descrever cabeçalhos de segurança
type SecurityHeader struct {
	Name        string
	Description string
	Expected    string
	Severity    string // Critical, High, Medium, Low
}

// Lista de cabeçalhos de segurança comumente verificados
var securityHeaders = []SecurityHeader{
	{
		Name:        "Strict-Transport-Security",
		Description: "Força conexões HTTPS",
		Expected:    "max-age=31536000; includeSubDomains; preload",
		Severity:    "Critical",
	},
	{
		Name:        "Content-Security-Policy",
		Description: "Previne XSS e injeção de dados",
		Expected:    "default-src 'self'",
		Severity:    "Critical",
	},
	{
		Name:        "X-Content-Type-Options",
		Description: "Previne MIME sniffing",
		Expected:    "nosniff",
		Severity:    "High",
	},
	{
		Name:        "X-Frame-Options",
		Description: "Previne clickjacking",
		Expected:    "DENY",
		Severity:    "High",
	},
	{
		Name:        "X-XSS-Protection",
		Description: "Proteção adicional contra XSS",
		Expected:    "1; mode=block",
		Severity:    "Medium",
	},
	{
		Name:        "Referrer-Policy",
		Description: "Controla como as informações de referência são enviadas",
		Expected:    "strict-origin-when-cross-origin",
		Severity:    "Medium",
	},
	{
		Name:        "Permissions-Policy",
		Description: "Controla quais recursos podem ser usados pelo site",
		Expected:    "camera=(), microphone=(), geolocation=()",
		Severity:    "Medium",
	},
	{
		Name:        "Cache-Control",
		Description: "Controla como o conteúdo é armazenado em cache",
		Expected:    "no-store, max-age=0",
		Severity:    "Medium",
	},
	{
		Name:        "Clear-Site-Data",
		Description: "Limpa dados do site no cliente",
		Expected:    "\"cache\",\"cookies\",\"storage\"",
		Severity:    "Low",
	},
	{
		Name:        "Cross-Origin-Embedder-Policy",
		Description: "Controla o carregamento de recursos cross-origin",
		Expected:    "require-corp",
		Severity:    "Low",
	},
	{
		Name:        "Cross-Origin-Opener-Policy",
		Description: "Isola o contexto de navegação",
		Expected:    "same-origin",
		Severity:    "Low",
	},
	{
		Name:        "Cross-Origin-Resource-Policy",
		Description: "Protege recursos de serem carregados cross-origin",
		Expected:    "same-origin",
		Severity:    "Low",
	},
	{
		Name:        "Access-Control-Allow-Origin",
		Description: "Controla quais sites podem acessar os recursos",
		Expected:    "specific origin or null",
		Severity:    "Medium",
	},
	{
		Name:        "Feature-Policy",
		Description: "Controla quais recursos são permitidos (legado)",
		Expected:    "camera 'none'; microphone 'none'",
		Severity:    "Low",
	},
	{
		Name:        "Server",
		Description: "Informações do servidor (ideal não expor)",
		Expected:    "não presente ou com informações limitadas",
		Severity:    "Low",
	},
	{
		Name:        "X-Powered-By",
		Description: "Informações da tecnologia (ideal não expor)",
		Expected:    "não presente",
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
	fmt.Println(colorPurple + colorBold + `
 ███████╗███████╗ ██████╗      ██╗  ██╗███████╗ █████╗ ██████╗ ███████╗██████╗ ███████╗
 ██╔════╝██╔════╝██╔════╝      ██║  ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝
 ███████╗█████╗  ██║     █████╗███████║█████╗  ███████║██║  ██║█████╗  ██████╔╝███████╗
 ╚════██║██╔══╝  ██║     ╚════╝██╔══██║██╔══╝  ██╔══██║██║  ██║██╔══╝  ██╔══██╗╚════██║
 ███████║███████╗╚██████╗      ██║  ██║███████╗██║  ██║██████╔╝███████╗██║  ██║███████║
 ╚══════╝╚══════╝ ╚═════╝      ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝` + colorReset)
	fmt.Println(colorYellow + colorBold + "                    📊 Security Headers Checker v" + version + " 🔒" + colorReset)
	fmt.Println(colorCyan + "═══════════════════════════════════════════════════════════════════════════════" + colorReset)
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

// Função principal para verificar cabeçalhos
func checkHeaders(target string) {
	// Determinar protocolo se não for especificado
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
		fmt.Printf("%sProtocolo não especificado. Usando: %s%s\n\n", colorYellow, target, colorReset)
	}

	fmt.Printf("%s[*] Conectando a %s...%s\n", colorCyan, target, colorReset)

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		fmt.Printf("%s[✗] Erro ao criar requisição: %s%s\n", colorRed, err, colorReset)
		return
	}

	// Simula um navegador para obter respostas mais realistas
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("%s[✗] Erro ao conectar: %s%s\n", colorRed, err, colorReset)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("%s[✓] Conexão estabelecida (HTTP %d)%s\n\n", colorGreen, resp.StatusCode, colorReset)
	fmt.Printf("%s[*] Analisando cabeçalhos de segurança...%s\n\n", colorCyan, colorReset)

	// Contadores para resumo final
	var present, missing, total int
	total = len(securityHeaders)

	// Imprimir cabeçalho da tabela
	fmt.Printf("%-35s %-15s %-10s %s\n", "CABEÇALHO", "ESTADO", "SEVERIDADE", "VALOR")
	fmt.Printf("%s%s%s\n", colorCyan, strings.Repeat("═", 100), colorReset)

	// Verificar cada cabeçalho de segurança
	for _, header := range securityHeaders {
		headerValue := resp.Header.Get(header.Name)
		
		if headerValue != "" {
			present++
			fmt.Printf("%-35s %s%-15s%s %s%-10s%s %s\n", 
				header.Name, 
				colorGreen, "PRESENTE", colorReset,
				getSeverityColor(header.Severity), header.Severity, colorReset,
				headerValue)
		} else {
			missing++
			fmt.Printf("%-35s %s%-15s%s %s%-10s%s %s\n", 
				header.Name, 
				colorRed, "AUSENTE", colorReset,
				getSeverityColor(header.Severity), header.Severity, colorReset,
				"-")
		}
	}

	// Exibir outros cabeçalhos que não estão na lista padrão, mas podem ser relevantes
	fmt.Printf("\n%s[*] Outros cabeçalhos encontrados:%s\n", colorCyan, colorReset)
	fmt.Printf("%s%s%s\n", colorCyan, strings.Repeat("═", 100), colorReset)
	
	otherHeadersFound := false
	for name, values := range resp.Header {
		isSecurityHeader := false
		for _, header := range securityHeaders {
			if strings.EqualFold(name, header.Name) {
				isSecurityHeader = true
				break
			}
		}
		
		if !isSecurityHeader {
			otherHeadersFound = true
			fmt.Printf("%-35s %s\n", name, strings.Join(values, ", "))
		}
	}
	
	if !otherHeadersFound {
		fmt.Println("Nenhum outro cabeçalho relevante encontrado.")
	}

	// Resumo final
	fmt.Printf("\n%s[*] Resumo da análise:%s\n", colorCyan, colorReset)
	fmt.Printf("%s%s%s\n", colorCyan, strings.Repeat("═", 100), colorReset)
	fmt.Printf("Total de cabeçalhos verificados: %d\n", total)
	fmt.Printf("Cabeçalhos presentes: %s%d (%.1f%%)%s\n", colorGreen, present, float64(present)/float64(total)*100, colorReset)
	fmt.Printf("Cabeçalhos ausentes: %s%d (%.1f%%)%s\n", colorRed, missing, float64(missing)/float64(total)*100, colorReset)
	
	// Pontuação de segurança
	score := calculateSecurityScore(resp.Header)
	fmt.Printf("\nPontuação de segurança: %s%d/100%s %s\n", getScoreColor(score), score, colorReset, getScoreEmoji(score))
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
		return "🔒 Excelente!"
	case score >= 70:
		return "👍 Bom"
	case score >= 50:
		return "⚠️ Regular"
	case score >= 30:
		return "⚠️ Insuficiente"
	default:
		return "🚨 Crítico"
	}
}

func main() {
	displayBanner()
	
	reader := bufio.NewReader(os.Stdin)
	
	fmt.Println("\nDigite o alvo a ser verificado (domínio, IP ou URL completa):")
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
