# Oralyzer

![Python](https://img.shields.io/badge/Python-3.x-blue)
![License](https://img.shields.io/badge/License-GPL--3.0-green)
![PRs](https://img.shields.io/badge/PRs-welcome-brightgreen)

A simple Python script that probes websites for Open Redirect vulnerabilities by
fuzzing the target URL with a large set of redirect payloads and reporting which
payloads the server follows to an external host.

## Usage

Oralyzer detects open redirects delivered via headers, JavaScript, and meta-tag
refresh, plus CRLF injection.

```
usage: oralyzer [-h] [-u URL] [-o EXPORT] [-l PATH] [-crlf]
                [-p PAYLOAD] [--proxy] [--wayback]
```

| Flag | Description |
| --- | --- |
| `-u URL` | Scan a single target |
| `-l PATH` | Scan multiple targets from a file (one URL per line) |
| `-p PAYLOAD` | Use a custom payloads file (defaults to bundled list) |
| `-o EXPORT` | Export all findings to a JSON file |
| `-crlf` | Scan for CRLF injection |
| `--wayback` | Fetch candidate URLs from web.archive.org |
| `--proxy` | Route requests through a proxy |

```sh
# single target
python oralyzer.py -u https://example.com/login

# export findings to JSON
python oralyzer.py -u https://example.com/login -o results.json

# many targets from a file
python oralyzer.py -l targets.txt

# CRLF injection scan
python oralyzer.py -u https://example.com/ -crlf

# harvest vulnerable-looking URLs from the wayback machine
python oralyzer.py -u example.com --wayback
```

Findings can be exported to a JSON array (`-o`). Redirect records look like:

```json
[
  {
    "type": "header",
    "request_url": "https://example.com/login?next=//evil.com",
    "payload": "//evil.com",
    "status_code": 302,
    "destination": "https://evil.com"
  }
]
```

Wayback records carry `target` and `found_url` instead.

## Installation

Either install as a package (gives you a global `oralyzer` command):

```sh
git clone https://github.com/r0075h3ll/Oralyzer.git
cd Oralyzer
pip install .
```

Or run straight from a checkout:

```sh
git clone https://github.com/r0075h3ll/Oralyzer.git
cd Oralyzer
pip install -r requirements.txt
python oralyzer.py -u https://example.com/
```
