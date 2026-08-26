# Oralyzer

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![License](https://img.shields.io/badge/License-GPL--3.0-green)
![PRs](https://img.shields.io/badge/PRs-welcome-brightgreen)

A Python tool that probes websites for Open Redirect vulnerabilities by fuzzing the target URL with redirect payloads and reporting which payloads the server follows to an external host.

## Features

- **Open Redirect Detection**: Header, JavaScript, and meta-tag redirects
- **CRLF Injection Scanning**: HTTP response splitting vulnerabilities
- **Wayback Machine Integration**: Harvest candidate URLs from archive.org
- **JSON Export**: Export findings for further analysis
- **Proxy Support**: Route requests through HTTP proxies

## Installation

### With pipx (recommended)

pipx installs CLI tools into isolated environments, so `oralyzer` works
system-wide without touching your system Python. This avoids the
`externally-managed-environment` error on Debian/Ubuntu (PEP 668).

```sh
# Install pipx if you don't have it
sudo apt install pipx
pipx ensurepath

# Install Oralyzer
pipx install oralyzer
```

### With pip in a virtual environment

If you prefer plain pip, create a venv first:

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

Or run directly without installing:

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

# Harvest URLs from Wayback Machine
oralyzer -u example.com --wayback

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
| `--wayback` | Fetch URLs from archive.org |
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

## Project Structure

```
src/oralyzer/
├── __init__.py          # Package initialization
├── __main__.py          # Module entry point
├── cli.py               # Command-line interface
├── scanner.py           # Main scanning orchestration
├── core/
│   ├── __init__.py
│   ├── http.py          # HTTP client with connection pooling
│   ├── payloads.py      # Payload generation and loading
│   ├── detection.py     # Response analysis
│   ├── crlf.py          # CRLF injection scanning
│   └── wayback.py       # Wayback Machine integration
└── data/
    └── payloads.txt     # Default payload list
```

## Development

```sh
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Type checking
mypy src/oralyzer

# Linting
ruff check src/oralyzer
```

## License

GPL-3.0

## Credits

Original author: r0075h3ll
