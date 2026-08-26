"""Main scanner orchestration for Oralyzer."""

from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, List, Optional, Tuple

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
        max_workers: int = 5,
    ):
        if max_workers < 1:
            raise ValueError("max_workers must be at least 1")
        if timeout < 1:
            raise ValueError("timeout must be at least 1")
        self.http_client = HttpClient(proxy=proxy, timeout=timeout)
        self.max_workers = max_workers

    def scan_redirect(
        self,
        url: str,
        payloads: List[str],
        progress_callback: Optional[Callable[[int, int], None]] = None,
        limit: Optional[int] = None,
        filter_type: Optional[str] = None,
        stop_event: Optional[threading.Event] = None,
    ) -> List[Finding]:
        """Scan a URL for open redirect vulnerabilities.

        Args:
            url: Target URL to scan.
            payloads: List of payloads to test.
            progress_callback: Optional callback(current, total) for progress updates.
            limit: Stop after finding this many vulnerabilities.
            filter_type: Only return findings of this type.
            stop_event: Optional event; scan stops early once set (used by scan_multiple
                to enforce a limit shared across concurrent workers).

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
            if stop_event is not None and stop_event.is_set():
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

    def scan_multiple(
        self,
        urls: List[str],
        payloads: List[str],
        scan_type: str = "redirect",
        progress_callback: Optional[Callable[[int, int], None]] = None,
        limit: Optional[int] = None,
        filter_type: Optional[str] = None,
    ) -> Tuple[List[Finding], List[str]]:
        """Scan multiple URLs concurrently.

        Returns:
            (findings, empty_urls) — empty_urls lists targets with no findings.
        """
        if scan_type not in ("redirect",):
            raise ValueError(f"unknown scan_type: {scan_type}")

        findings: List[Finding] = []
        empty_urls: List[str] = []
        stop_event = threading.Event()
        lock = threading.Lock()
        requests_done = 0

        def worker_progress(current: int, total: int) -> None:
            nonlocal requests_done
            with lock:
                requests_done += 1
                count = requests_done
            if progress_callback:
                progress_callback(count, len(urls) * total)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_url = {
                executor.submit(
                    self.scan_redirect,
                    url,
                    payloads,
                    worker_progress,
                    limit,
                    filter_type,
                    stop_event,
                ): url
                for url in urls
            }
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result()
                    with lock:
                        findings.extend(result)
                        if not result:
                            empty_urls.append(url)
                        if limit and len(findings) >= limit:
                            stop_event.set()
                except Exception:
                    logger.exception("Scan failed for %s", url)
        return findings[:limit] if limit else findings, empty_urls

    def scan_wayback(self, url: str) -> List[dict]:
        """Fetch vulnerable-looking URLs from Wayback Machine."""
        client = WaybackClient(self.http_client)
        matched_urls = client.get_matching_urls(url)

        return [
            {"type": "wayback", "target": url, "found_url": found_url}
            for found_url in matched_urls
        ]
