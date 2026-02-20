# SEC-HEADERS-CHECK

![Banner](https://img.shields.io/badge/SHCH-v2.0.0--demo-purple)
![Go](https://img.shields.io/badge/Go-1.18+-blue)
![Security](https://img.shields.io/badge/Security-Headers-green)
![License](https://img.shields.io/badge/License-Apache%202.0-blue)
![HTTP](https://img.shields.io/badge/Protocol-HTTP/1.1%20%7C%202.0-orange)
![Pentest](https://img.shields.io/badge/Purpose-Pentesting-critical)

**SEC-HEADERS-CHECK** is a command-line tool written in Go to verify the presence and configuration of HTTP security headers on websites. It automates the process of checking important HTTP headers that can mitigate various types of web attacks.

## Features

- Verification of 16 critical HTTP security headers
- Support for concurrent endpoint testing
- Supports domains, full URLs, or IP address inputs
- Colourful and user-friendly terminal interface
- Detailed output with security scoring and consistency checks
- Output formats: terminal, JSON, and CSV
- Auto-detection of HTTP/HTTPS protocols
- Identification of headers that may reveal sensitive information

## Installation

### Prerequisites

- Go 1.18 or higher

### Compiling

```bash
# Clone the repository
git clone https://github.com/had-nu/sec-headers-check.git
cd sec-headers-check

# Download dependencies (if applicable)
go mod tidy

# Build the binary
go build -o sec-headers-check ./cmd/masthead

# Run the tool
./sec-headers-check
```

## Usage

Run the binary and follow the on-screen prompts, or use the flags to automate testing:

```bash
# Interactive mode
./sec-headers-check

# Command-line flags
./sec-headers-check -target example.com
./sec-headers-check -target example.com -output json
./sec-headers-check -target example.com -output csv -out report.csv
```

### Available Flags:
- `-target`: The target domain, IP, or full URL to scan. Falls back to interactive prompt if omitted.
- `-output`: The report output format. Acceptable values are `terminal` (default), `json`, or `csv`.
- `-out`: Write the output to a specified file instead of stdout (e.g. `-out results.json`).

The tool will automatically detect your input format and append the `https://` protocol if missing.

## Verified Headers

The application verifies the presence and configuration of the following HTTP security headers:

| Header | Severity | Description | Protection |
|-----------|------------|-----------|----------|
| **Strict-Transport-Security** | Critical | Enforces HTTPS connections | Protects against protocol downgrade and MITM attacks |
| **Content-Security-Policy** | Critical | Defines trusted sources for resources | Mitigates XSS and data injection |
| **X-Content-Type-Options** | High | Prevents MIME sniffing | Stops MIME-sniffing based attacks |
| **X-Frame-Options** | High | Controls whether the page can be framed | Prevents clickjacking |
| **X-XSS-Protection** | Medium | Activates browser XSS filters | Additional layer of XSS protection |
| **Referrer-Policy** | Medium | Controls the referrer information sent | Protects user privacy and stops information leakage |
| **Permissions-Policy** | Medium | Controls allowed browser features | Limits hardware/software features like camera or geolocation |
| **Cache-Control** | Medium | Controls content caching | Stops sensitive data from being cached |
| **Clear-Site-Data** | Low | Clears site data from the browser | Useful for logout and privacy protection |
| **Cross-Origin-Embedder-Policy** | Low | Controls cross-origin embedded resources | Part of COOP+COEP protection |
| **Cross-Origin-Opener-Policy** | Low | Isolates browsing contexts | Protects against window-based attacks |
| **Cross-Origin-Resource-Policy** | Low | Protects resources from being loaded cross-origin | Prevents cross-origin information leaks |
| **Access-Control-Allow-Origin** | Medium | Controls CORS | Prevents unauthorised access to resources |
| **Feature-Policy** (legacy) | Low | Controls allowed features (legacy) | Similar to Permissions-Policy |
| **Server** | Low | Identifies the web server software | May expose vulnerable versions if overly descriptive |
| **X-Powered-By** | Low | Identifies backend technologies | May expose vulnerable versions if present |

## Internal Architecture Diagram

```
┌──────────────────────────┐
│        CLI User          │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│     Target Validation    │
│   isValidURL/IP/Domain   │
└────────────┬─────────────┘
             ▼
┌──────────────────────────┐
│ Concurrent Verification  │
│   Multiple Endpoints     │
└────────────┬─────────────┘
             ▼
┌──────────────────────────┐
│  Request Preparation &   │
│ HTTP Receive / Send      │
└────────────┬─────────────┘
             ▼
┌─────────────────────────────┐
│ Comparison vs Static List   │◄────────────┐
│      `securityHeaders`      │             │
└────────────┬────────────────┘             │
             ▼                              │
┌─────────────────────────────┐             │
│ Score & Analysis generation │             │
│ `ScoreHeaders` / `Build`    │             │
└────────────┬────────────────┘             │
             ▼                              │
┌─────────────────────────────┐             │
│   Report Output Formatting  │             │
│ Terminal / JSON / CSV       │             │
└─────────────────────────────┘             │
                                            │
┌───────────────────────────────────────────┘
│       `securityHeaders` Static List
└────────────────────────────────────────────
```

## Why are these headers important?

### Critical Headers

1. **Strict-Transport-Security (HSTS)**
   - **What it does:** Forces the browser to use HTTPS instead of HTTP for future communications.
   - **Protects against:** Downgrade attacks and traffic interception.
   - **Recommended configuration:** `max-age=31536000; includeSubDomains; preload`
   - **Impact of absence:** Vulnerable to MITM attacks; possible interception of sensitive data.

2. **Content-Security-Policy (CSP)**
   - **What it does:** Defines which graphical or code resources can be loaded and from where.
   - **Protects against:** XSS, data injection, and clickjacking.
   - **Recommended configuration:** Tailored for each application, starting with `default-src 'self'`.
   - **Impact of absence:** Higher susceptibility to XSS and injection of malicious content.

### High Severity Headers

3. **X-Content-Type-Options**
   - **What it does:** Stops the browser from "sniffing" files as a different MIME type.
   - **Protects against:** MIME sniffing and content injection.
   - **Recommended configuration:** `nosniff`
   - **Impact of absence:** Files might be interpreted incorrectly, introducing security vulnerabilities.

4. **X-Frame-Options**
   - **What it does:** Controls if a browser can render the page inside a `<frame>`, `<iframe>` or `<object>`.
   - **Protects against:** Clickjacking.
   - **Recommended configuration:** `DENY` or `SAMEORIGIN`
   - **Impact of absence:** Risk of clickjacking where a site is loaded into an invisible iframe overlay.

### Medium Severity Headers

5. **X-XSS-Protection**
   - **What it does:** Turns on built-in XSS filters in legacy web browsers.
   - **Protects against:** A subset of cross-site scripting attacks.
   - **Recommended configuration:** `1; mode=block`
   - **Note:** Considered legacy in modern browsers, but useful for compatibility margins.

6. **Referrer-Policy**
   - **What it does:** Instructs how much referrer information is supplied with requests.
   - **Protects against:** Unauthorised cross-origin information leakage.
   - **Recommended configuration:** `strict-origin-when-cross-origin`

7. **Permissions-Policy** (replaces Feature-Policy)
   - **What it does:** Allows or denies specific browser capabilities and APIs (e.g. vibration, webcam).
   - **Protects against:** Unauthorised device tracking and abuse of hardware.
   - **Example configuration:** `camera=(), microphone=(), geolocation=()`

8. **Cache-Control**
   - **What it does:** Dictates how, where, and for how long downstream responses can be cached.
   - **Protects against:** Data leakage via caching layers or local browsers.
   - **Recommended configuration for sensitive data:** `no-store, max-age=0`

9. **Access-Control-Allow-Origin**
   - **What it does:** Dictates which external origins can access the payload via CORS.
   - **Protects against:** Unauthorised cross-origin data retrieval.
   - **Recommended configuration:** Needs to be explicitly targeted; avoid `*` for authenticated APIs.

### Low Severity Headers

10. **Clear-Site-Data**
    - **What it does:** Clears locally retained site data (cookies, storage, cache).
    - **Protects against:** Latent persistent sensitive data.
    - **Recommended usage:** Primarily on logout endpoints.

11. **Cross-Origin-Embedder-Policy**
    - **What it does:** Prevents cross-origin documents from loading embedded resources unless explicitly allowed.
    - **Recommended configuration:** `require-corp`

12. **Cross-Origin-Opener-Policy**
    - **What it does:** Ensures an isolated browsing context from external windows and tabs.
    - **Recommended configuration:** `same-origin`

13. **Cross-Origin-Resource-Policy**
    - **What it does:** Stops other domains from directly reading certain site resources.
    - **Protects against:** Side-channel attacks (like Spectre).
    - **Recommended configuration:** `same-origin`

14. **Feature-Policy** (legacy)
    - **What it does:** Precursor to the modern `Permissions-Policy`.
    - **Note:** Retain solely for backward compatibility with antiquated browser deployments.

15. **Server**
    - **What it does:** Outlines the software running the backend.
    - **Protects against:** Exposing software versions to prospective attackers.
    - **Recommended configuration:** Omit entirely, or strip versions down to a generic placeholder.

16. **X-Powered-By**
    - **What it does:** Indicates backend scripting or framework technology.
    - **Protects against:** Exposing structural framework vectors.
    - **Recommended configuration:** Always remove entirely via reverse-proxy or code.

## Interpreting Results

The tool calculates a qualitative score scaled between `0` and `100` depending on the aggregation of specific headers and their individual importance. 

### Scoring Criteria:
- **90-100**: Excellent security posture 
- **70-89**: Good posture; although possessing minor oversights
- **50-69**: Average setup, requiring immediate review
- **30-49**: Insufficient configuration showing an elevated risk of breach
- **0-29**: Critical configuration; demands immediate remediation

### Output Demonstration (Terminal)

The core validation cycle tests several endpoints implicitly and processes output asynchronously:

```
[*] Alvo: https://example.com
[*] Gerado em: 2026-02-20 17:00:00 UTC

[✓] /                    HTTP 200
[✓] /api                 HTTP 404
[✓] /login               HTTP 404

[*] Análise: /
[*] Método: GET | Status: HTTP 200
═════════════════════════════════════════════════════════════════════════════════════════════
CABEÇALHO                           ESTADO          SEVERIDADE VALOR
─────────────────────────────────────────────────────────────────────────────────────────────
Strict-Transport-Security          PRESENTE        Critical   max-age=31536000
Content-Security-Policy            AUSENTE         Critical   -
X-Content-Type-Options             PRESENTE        High       nosniff...

Cabeçalhos presentes: 2/16 (12.5%)
Pontuação: 55/100  [!] Regular
...
```

*(Note: Although the README is in English, the application's terminal interface currently retains its Portuguese localisation.)*

## License

This project is distributed under the Apache 2.0 License - see the LICENSE file for details.

## Contributions

Contributions are always welcome! Feel free to open issues or submit pull requests with improvements, bug fixes, or new features.

---

Developed for the security community.
