# Oralyzer

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![License](https://img.shields.io/badge/License-GPL--3.0-green)
![PRs](https://img.shields.io/badge/PRs-welcome-brightgreen)

A Python tool for Open Redirect vulnerabilities. It fuzzes the target URL with redirect payloads and reports which ones the server actually follows to an external host.

## Features

- **Open Redirect Detection**: Header, JavaScript, and meta-tag redirects
- **CRLF Injection Scanning**: HTTP response splitting vulnerabilities
- **URL Discovery**: Harvest candidate URLs from Common Crawl's index
- **JSON Export**: Export findings for further analysis
- **Proxy Support**: Route requests through HTTP proxies

## Installation

### With pipx (recommended)

pipx installs CLI tools into isolated environments, so `oralyzer` works system-wide without touching your system Python — and you sidestep the `externally-managed-environment` error on Debian/Ubuntu (PEP 668).

```sh
# Install pipx if you don't have it
sudo apt install pipx
pipx ensurepath

# Install Oralyzer
pipx install oralyzer
```

### With pip in a virtual environment

Prefer plain pip? Create a venv first:

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install oralyzer
```

### From source

```sh
git clone https://github.com/r0075h3ll/Oralyzer.git
cd Oralyzer
pipx install .
# or, inside a venv:
pip install .
```

Or skip installing altogether and run it directly:

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install .
python -m oralyzer -u https://example.com/
```

## Usage

```sh
# Single target
oralyzer -u https://example.com/login

# Multiple targets from file
oralyzer -l targets.txt

# Export findings to JSON
oralyzer -u https://example.com/login -o results.json

# CRLF injection scan
oralyzer -u https://example.com/ -crlf

# Harvest URLs from Common Crawl
oralyzer -u example.com --discover

# Use proxy
oralyzer -u https://example.com/ --proxy http://127.0.0.1:8080

# Verbose logging
oralyzer -u https://example.com/ -v

# Concurrent scanning with custom workers
oralyzer -l targets.txt --workers 10 -o results.json
```

### Command-line Options

| Option | Description |
|--------|-------------|
| `-u, --url URL` | Scan a single target |
| `-l, --list PATH` | Scan multiple targets from a file |
| `-p, --payload PATH` | Use custom payloads file |
| `-o, --output PATH` | Export findings to JSON |
| `-crlf` | Scan for CRLF injection |
| `--discover` | Harvest candidate URLs from Common Crawl |
| `--proxy URL` | Route requests through proxy |
| `--timeout SECONDS` | Request timeout (default: 10) |
| `--workers N` | Concurrent workers (default: 5) |
| `--limit N` | Stop after N findings |
| `--filter TYPE` | Only report: `header`, `javascript`, `meta`, `crlf` |
| `-q, --quiet` | Only show findings |
| `--no-color` | Disable colored output |
| `-v, --verbose` | Enable verbose logging |

## Output Format

Findings are exported as JSON:

```json
[
  {
    "type": "header",
    "request_url": "https://example.com/login?next=//evil.com",
    "payload": "//evil.com",
    "status_code": 302,
    "destination": "https://evil.com"
  },
  {
    "type": "javascript",
    "request_url": "https://example.com/page",
    "payload": "//evil.com",
    "status_code": 200,
    "sources": ["location.href", "document.URL"]
  }
]
```