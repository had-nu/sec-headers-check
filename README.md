# MASTHEAD (sec-headers-check)

![Banner](https://img.shields.io/badge/Masthead-v2.0.0--demo-purple)
![Go](https://img.shields.io/badge/Go-1.18+-blue)
![Security](https://img.shields.io/badge/Security-Headers-green)
![License](https://img.shields.io/badge/License-Apache%202.0-blue)
![HTTP](https://img.shields.io/badge/Protocol-HTTP/1.1%20%7C%202.0-orange)
![Pentest](https://img.shields.io/badge/Purpose-Pentesting-critical)

**MASTHEAD** (formerly `sec-headers-check`) is a command-line tool written in Go to verify the presence and configuration of HTTP security headers on websites. 

In version 2.0.0, the tool introduces **Dynamic Endpoint Discovery**. Instead of testing a hardcoded list of endpoints, Masthead automatically crawls the target and probes for common administrative or hidden paths, adapting its security scan to the actual topology of the web application.

## Key Features

- **Dynamic Endpoint Mapping**: Uses a hybrid approach (web crawling + path probing) to discover internal links and hidden endpoints like `/api/v1` or `/admin` before scanning.
- **Verification of 16 Critical Headers**: Ensures comprehensive coverage for modern security standards like HSTS, CSP, and CORS policies.
- **Concurrent Execution**: Fast, asynchronous scraping and header verification.
- **Multiple Output Formats**: Supports `terminal` (colorful, user-friendly), `json`, and `csv` for pipeline integration.
- **Consistency Checks**: Cross-references missing headers across all discovered endpoints to ensure uniformity.

## Installation

### Prerequisites

- Go 1.18 or higher

### Compiling

```bash
# Clone the repository
git clone https://github.com/had-nu/masthead.git
cd masthead

# Download dependencies
go mod tidy

# Build the binary
go build -o masthead ./cmd/masthead

# Run the tool
./masthead
```

## Usage

Simply run the binary and follow the on-screen prompts, or use the command-line flags to automate testing in your CI/CD pipelines.

```bash
# Interactive mode
./masthead

# Command-line flags
./masthead -target example.com
./masthead -target example.com -max-endpoints 25
./masthead -target example.com -output json
./masthead -target example.com -output csv -out report.csv
```

### Available Flags

- `-target`: The target domain, IP, or full URL to scan. Falls back to an interactive prompt if omitted.
- `-max-endpoints`: The maximum number of endpoints to map dynamically via the crawler (default: `15`).
- `-output`: The report output format. Acceptable values are `terminal` (default), `json`, or `csv`.
- `-out`: Write the output to a specified file instead of stdout (e.g. `-out results.json`).

The tool will automatically detect your input format and append the `https://` protocol if missing.

## Verified Headers

Masthead automatically checks for 16 modern and legacy security headers, including:
- **Strict-Transport-Security (HSTS)** and **Content-Security-Policy (CSP)** (Critical severity)
- **X-Frame-Options** and **X-Content-Type-Options** (High severity)
- Various **Cross-Origin** policies (CORS, COEP, COOP, CORP)
- Information disclosure headers like **Server** and **X-Powered-By**

## Interpreting Results

Masthead evaluates the scanned headers across all endpoints and calculates an overall score between `0` and `100`. 
- **90-100**: Excellent security posture 
- **50-89**: Average to Good posture (minor oversights)
- **0-49**: Insufficient configuration showing an elevated risk of breach

The interactive terminal UI (currently presented in Portuguese) outputs a clear visual table comparing missing vs. present headers across all discovered paths, as well as a consistency check graph. You can export these reports to `JSON` or `CSV` format for easier pipeline integration.

## License

This project is distributed under the Apache 2.0 License - see the LICENSE file for details.

## Contributions

Contributions are always welcome! Feel free to open issues or submit pull requests with improvements, bug fixes, or new features.

---
