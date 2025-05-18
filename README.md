# SEC-HEADERS-CHECK

![Banner](https://img.shields.io/badge/SHCH-v1.0.0--demo-purple)
![Go](https://img.shields.io/badge/Go-1.18+-blue)
![Security](https://img.shields.io/badge/Security-Headers-green)
![License](https://img.shields.io/badge/License-Apache-2.0)

**SEC-HEADERS-CHECK** é uma ferramenta de linha de comando escrita em Go para verificar a presença e a configuração de cabeçalhos HTTP de segurança em websites. Ela automatiza o processo de verificação de cabeçalhos HTTP importantes que podem mitigar diversos tipos de ataques web.

## Funcionalidades

- Verificação de 16 cabeçalhos de segurança HTTP importantes
- Suporte para entrada de domínio, URL completa ou endereço IP
- Interface colorida e amigável no terminal
- Análise detalhada com pontuação de segurança
- Detecção automática do protocolo (HTTP/HTTPS)
- Exibição de cabeçalhos adicionais que podem revelar informações sensíveis

## Instalação

### Pré-requisitos

- Go 1.18 ou superior

### Instalando

```bash
# Clone o repositório
git clone https://github.com/had-nu/sec-headers-check.git
cd sec-headers-check

# Construa o binário
go build -o sec-headers-check main.go

# Execute a ferramenta
./sec-headers-check
```

## Uso

Execute o binário e siga as instruções na tela:

```bash
./sec-headers-check
```

Quando solicitado, insira o alvo que deseja verificar. Pode ser:
- Um domínio simples (exemplo.com)
- Uma URL completa (https://exemplo.com)
- Um endereço IP (192.168.1.1)

A ferramenta detectará automaticamente o formato da entrada e adicionará o protocolo https:// se necessário.

## Cabeçalhos Verificados

A ferramenta verifica a presença e configuração dos seguintes cabeçalhos HTTP de segurança:

| Cabeçalho | Severidade | Descrição | Proteção |
|-----------|------------|-----------|----------|
| **Strict-Transport-Security** | Crítico | Define que o site só deve ser acessado via HTTPS | Protege contra ataques de downgrade e MITM (Man-in-the-Middle) |
| **Content-Security-Policy** | Crítico | Define origens confiáveis para recursos | Mitiga ataques XSS e injeção de dados |
| **X-Content-Type-Options** | Alto | Evita que o navegador faça MIME sniffing | Previne ataques baseados em MIME sniffing |
| **X-Frame-Options** | Alto | Controla se a página pode ser exibida em frames | Previne ataques de clickjacking |
| **X-XSS-Protection** | Médio | Ativa filtros XSS do navegador | Camada adicional de proteção contra XSS |
| **Referrer-Policy** | Médio | Controla informações de referência enviadas | Protege a privacidade do usuário e previne vazamento de informações |
| **Permissions-Policy** | Médio | Controla recursos do navegador permitidos | Limita recursos como câmera, microfone e localização |
| **Cache-Control** | Médio | Controla como o conteúdo é armazenado em cache | Previne que dados sensíveis sejam cacheados |
| **Clear-Site-Data** | Baixo | Limpa dados do site no navegador | Útil para logout e proteção de privacidade |
| **Cross-Origin-Embedder-Policy** | Baixo | Controla recursos incorporados cross-origin | Parte da proteção COOP+COEP |
| **Cross-Origin-Opener-Policy** | Baixo | Isola contextos de navegação | Protege contra ataques baseados em janela |
| **Cross-Origin-Resource-Policy** | Baixo | Protege recursos de serem carregados cross-origin | Previne vazamentos de informações entre origens |
| **Access-Control-Allow-Origin** | Médio | Controla o CORS | Previne acessos não autorizados a recursos |
| **Feature-Policy** (legado) | Baixo | Controla recursos permitidos (versão legada) | Similar ao Permissions-Policy |
| **Server** | Baixo | Informações sobre o servidor web | Pode expor versões vulneráveis se configurado incorretamente |
| **X-Powered-By** | Baixo | Informações sobre a tecnologia do servidor | Pode expor versões vulneráveis se configurado incorretamente |

## Por Que Estes Cabeçalhos São Importantes

### Cabeçalhos Críticos

1. **Strict-Transport-Security (HSTS)**
   - **O que faz:** Força o navegador a usar HTTPS em vez de HTTP para comunicações futuras
   - **Proteção contra:** Ataques de downgrade e interceptação de tráfego
   - **Configuração recomendada:** `max-age=31536000; includeSubDomains; preload`
   - **Impacto da ausência:** Vulnerabilidade a ataques MITM, possibilidade de interceptação de dados sensíveis

2. **Content-Security-Policy (CSP)**
   - **O que faz:** Define quais recursos podem ser carregados e de onde
   - **Proteção contra:** XSS, injeção de dados, clickjacking
   - **Configuração recomendada:** Personalizada para cada aplicação, começando com `default-src 'self'`
   - **Impacto da ausência:** Maior vulnerabilidade a ataques XSS e injeção de conteúdo malicioso

### Cabeçalhos de Alta Severidade

3. **X-Content-Type-Options**
   - **O que faz:** Impede que o navegador interprete arquivos como um tipo MIME diferente
   - **Proteção contra:** MIME sniffing e ataques de injeção de conteúdo
   - **Configuração recomendada:** `nosniff`
   - **Impacto da ausência:** Arquivos podem ser interpretados incorretamente, levando a vulnerabilidades de segurança

4. **X-Frame-Options**
   - **O que faz:** Controla se o navegador pode renderizar a página em um `<frame>`, `<iframe>` ou `<object>`
   - **Proteção contra:** Clickjacking
   - **Configuração recomendada:** `DENY` ou `SAMEORIGIN`
   - **Impacto da ausência:** Risco de ataques de clickjacking onde a página é carregada em um iframe invisível

### Cabeçalhos de Média Severidade

5. **X-XSS-Protection**
   - **O que faz:** Ativa filtros de XSS integrados em navegadores antigos
   - **Proteção contra:** Alguns tipos de ataques XSS
   - **Configuração recomendada:** `1; mode=block`
   - **Nota:** Considerado legado em navegadores modernos, mas ainda útil para compatibilidade

6. **Referrer-Policy**
   - **O que faz:** Controla quanta informação de referência é incluída com requisições
   - **Proteção contra:** Vazamento de informações entre origens
   - **Configuração recomendada:** `strict-origin-when-cross-origin`

7. **Permissions-Policy** (substitui Feature-Policy)
   - **O que faz:** Permite ou bloqueia certas APIs do navegador e recursos
   - **Proteção contra:** Abusos de recursos e rastreamento
   - **Exemplo de configuração:** `camera=(), microphone=(), geolocation=()`

8. **Cache-Control**
   - **O que faz:** Determina como, onde e por quanto tempo as respostas são cacheadas
   - **Proteção contra:** Vazamento de informações via cache
   - **Configuração recomendada para dados sensíveis:** `no-store, max-age=0`

9. **Access-Control-Allow-Origin**
   - **O que faz:** Define quais origens podem acessar o recurso via CORS
   - **Proteção contra:** Acesso não autorizado a recursos entre origens
   - **Configuração recomendada:** Específica para o caso de uso, nunca `*` para APIs autenticadas

### Cabeçalhos de Baixa Severidade

10. **Clear-Site-Data**
    - **O que faz:** Instrui o navegador a limpar dados armazenados para o site
    - **Proteção contra:** Persistência de dados sensíveis
    - **Uso recomendado:** Em páginas de logout

11. **Cross-Origin-Embedder-Policy**
    - **O que faz:** Controla quais recursos podem ser carregados por documentos cross-origin
    - **Proteção contra:** Vazamento de informações entre origens
    - **Configuração recomendada:** `require-corp`

12. **Cross-Origin-Opener-Policy**
    - **O que faz:** Isola o contexto de navegação do site
    - **Proteção contra:** Ataques baseados em navegação entre janelas
    - **Configuração recomendada:** `same-origin`

13. **Cross-Origin-Resource-Policy**
    - **O que faz:** Previne que outros sites carreguem recursos diretamente
    - **Proteção contra:** Vazamento de informações e ataques side-channel
    - **Configuração recomendada:** `same-origin`

14. **Feature-Policy** (legado)
    - **O que faz:** Versão anterior do Permissions-Policy
    - **Proteção contra:** Os mesmos riscos cobertos pelo Permissions-Policy
    - **Nota:** Mantido para compatibilidade, mas prefira usar Permissions-Policy

15. **Server**
    - **O que faz:** Identifica o software do servidor
    - **Proteção contra:** Revelar informações potencialmente sensíveis
    - **Configuração recomendada:** Remover ou minimizar informações

16. **X-Powered-By**
    - **O que faz:** Identifica a tecnologia de back-end
    - **Proteção contra:** Revelar informações potencialmente sensíveis
    - **Configuração recomendada:** Remover completamente

## Interpretando os Resultados

A ferramenta fornece uma pontuação de segurança baseada nos cabeçalhos encontrados e em sua importância. A pontuação é calculada considerando:

- A presença do cabeçalho
- A importância (severidade) do cabeçalho
- Em alguns casos, a qualidade da configuração

### Pontuação:
- **90-100**: Excelente configuração de segurança
- **70-89**: Boa configuração, mas com espaço para melhorias
- **50-69**: Configuração regular, precisa de atenção
- **30-49**: Configuração insuficiente, risco de segurança aumentado
- **0-29**: Configuração crítica, necessita intervenção imediata

## Licença

Este projeto está licenciado sob a Apache 2.0 - veja o arquivo LICENSE para detalhes.

## Contribuições

Contribuições são bem-vindas! Sinta-se à vontade para abrir issues ou enviar pull requests com melhorias, correções de bugs ou novas funcionalidades.

---

Desenvolvido com ❤️ para a comunidade de segurança
