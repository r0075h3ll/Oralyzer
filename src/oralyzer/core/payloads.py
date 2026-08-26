"""Payload generation and loading for Oralyzer."""

from __future__ import annotations

from pathlib import Path
from typing import List, Tuple
from urllib.parse import parse_qs, urlparse, urlunparse

DEFAULT_PAYLOADS_PATH = Path(__file__).parent.parent / "data" / "payloads.txt"


def load_payloads(path: Path = DEFAULT_PAYLOADS_PATH) -> List[str]:
    """Load payloads from file."""
    return path.read_text(encoding="utf-8").splitlines()


def generate_variants(url: str, payloads: List[str]) -> List[str]:
    """Generate regex-bypass variants using the target host."""
    root = urlparse(url).netloc
    variants = []
    for payload in payloads:
        variants.append(f"{payload}.{root}")
        variants.append(f"{payload}/{root}")
    return variants


def build_test_cases(
    url: str, payloads: List[str]
) -> Tuple[List[dict], List[str], str] | Tuple[List[str], List[str]]:
    """Build injected URLs/params for a target and payload list.

    Returns:
        If URL has query params: (queries, sent_payloads, base_url)
        Otherwise: (urls, sent_payloads)
    """
    if not urlparse(url).scheme:
        url = "http://" + url

    variants = generate_variants(url, payloads)
    parsed = urlparse(url)

    if parsed.query and "=" in parsed.query:
        query_params = parse_qs(parsed.query)
        parsed_url = list(parsed)
        parsed_url[-2] = ""
        base_url = urlunparse(parsed_url)

        queries = []
        sent = []

        for key, values in query_params.items():
            original_values = values.copy()

            for payload in payloads + variants:
                query_dict = {k: v.copy() for k, v in query_params.items()}
                query_dict[key] = [payload]
                flat_query = {k: v[0] if len(v) == 1 else v for k, v in query_dict.items()}
                queries.append(flat_query)
                sent.append(payload)

            query_params[key] = original_values

        return queries, sent, base_url

    urls = []
    sent = []

    if not url.endswith("/"):
        url += "/"

    for payload in payloads + variants:
        urls.append(url + payload)
        sent.append(payload)

    return urls, sent
