"""Main scanner orchestration for Oralyzer."""

from __future__ import annotations

import logging
from typing import Callable, List, Optional

import requests

from .core import (
    Finding,
    HttpClient,
    ResponseAnalyzer,
    WaybackClient,
    build_test_cases,
)

logger = logging.getLogger(__name__)


class Scanner:
    """Orchestrates vulnerability scanning."""

    def __init__(
        self,
        proxy: Optional[str] = None,
        timeout: int = 10,
    ):
        self.http_client = HttpClient(proxy=proxy, timeout=timeout)

    def scan_redirect(
        self,
        url: str,
        payloads: List[str],
        progress_callback: Optional[Callable[[int, int], None]] = None,
        limit: Optional[int] = None,
        filter_type: Optional[str] = None,
    ) -> List[Finding]:
        """Scan a URL for open redirect vulnerabilities.

        Args:
            url: Target URL to scan.
            payloads: List of payloads to test.
            progress_callback: Optional callback(current, total) for progress updates.
            limit: Stop after finding this many vulnerabilities.
            filter_type: Only return findings of this type.

        Returns:
            List of findings.
        """
        analyzer = ResponseAnalyzer(payloads)
        findings: List[Finding] = []

        cases = build_test_cases(url, payloads)
        targets: List[tuple[str, Optional[dict], str]]
        if len(cases) == 3:
            queries, sent_payloads, base_url = cases
            targets = [(base_url, q, p) for q, p in zip(queries, sent_payloads)]
        else:
            urls, sent_payloads = cases
            targets = [(u, None, p) for u, p in zip(urls, sent_payloads)]

        total = len(targets)
        for i, (target, params, payload) in enumerate(targets, 1):
            if limit and len(findings) >= limit:
                break

            if progress_callback:
                progress_callback(i, total)

            try:
                response = self.http_client.get(target, params=params)
                finding = analyzer.analyze_redirect(response, payload)
                if finding and (filter_type is None or finding.type == filter_type):
                    findings.append(finding)
            except requests.exceptions.Timeout:
                logger.warning("Timeout for %s", target)
            except requests.exceptions.RequestException as e:
                logger.warning("Request failed: %s", e)

        return findings

    def scan_wayback(self, url: str) -> List[dict]:
        """Fetch vulnerable-looking URLs from Wayback Machine."""
        client = WaybackClient(self.http_client)
        matched_urls = client.get_matching_urls(url)

        return [
            {"type": "wayback", "target": url, "found_url": found_url}
            for found_url in matched_urls
        ]
