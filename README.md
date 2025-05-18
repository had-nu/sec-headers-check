# HTTP Security Headers Checker (Go)
Este é um script simples escrito em Go para realizar a verificação automatizada de cabeçalhos HTTP de segurança em aplicações web. Ele realiza uma requisição HTTP para o domínio informado e verifica a presença de cabeçalhos de segurança recomendados, emitindo um diagnóstico simples sobre quais estão presentes e quais estão ausentes.

# Como usar
1. Pré-requisitos: Ter o Go instalado (versão 1.16+).
2. Clone o repositório:

``` bash
# Clonar o repositório
git clone https://github.com/had-nu/sec-headers-check.git
cd sec-headers-check

# Executar o verificador em Go
go run main.go
```
