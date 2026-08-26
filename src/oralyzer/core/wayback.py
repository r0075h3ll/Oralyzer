"""Wayback Machine CDX URL discovery for Oralyzer."""

import datetime
import logging
import re
from typing import List
from urllib.parse import unquote

import requests

from .http import HttpClient

logger = logging.getLogger(__name__)

DORKS = [
    r".*\?next=.*",
    r".*\?url=.*",
    r".*\?target=.*",
    r".*\?rurl=.*",
    r".*\/dest=.*",
    r".*\/destination=.*",
    r".*\?redir=.*",
    r".*\?redirect_uri=.*",
    r".*\?return=.*",
    r".*\?return_path.*",
    r".*\/cgi-bin\/redirect\.cgi\?.*",
    r".*\?checkout_url=.*",
    r".*\?image_url=.*",
    r".*\/out\?.*",
    r".*\?continue=.*",
    r".*\?view=.*",
    r".*\/redirect\/.*",
    r".*\?go=.*",
    r".*\?redirect=.*",
    r".*\?externallink=.*",
    r".*\?nextURL=.*",
]


class WaybackClient:
    """Client for querying the Wayback Machine CDX API."""

    def __init__(self, http_client: HttpClient):
        self.http_client = http_client
        self._dork_regex = re.compile("|".join(DORKS), re.IGNORECASE)

    def fetch_urls(self, url: str) -> List[str]:
        """Query CDX API for snapshots from the last two years."""
        today = datetime.date.today()
        from_year = today.year - 2
        to_year = today.year

        cdx_url = (
            f"https://web.archive.org/cdx/search/cdx?url={url}*"
            f"&output=json&collapse=urlkey&filter=statuscode:200"
            f"&limit=1000&from={from_year}&to={to_year}"
        )

        try:
            response = self.http_client.get(cdx_url)
        except requests.exceptions.RequestException:
            logger.warning("Failed to fetch from CDX API")
            return []

        try:
            data = response.json()
        except ValueError:
            logger.warning("CDX API returned invalid JSON")
            return []

        if not isinstance(data, list):
            return []

        urls = []
        for row in data[1:1001]:
            if isinstance(row, list) and len(row) > 2 and isinstance(row[2], str):
                urls.append(unquote(row[2]))

        return urls

    def get_matching_urls(self, url: str) -> List[str]:
        """Fetch URLs and filter by dork patterns."""
        return [u for u in self.fetch_urls(url) if self._dork_regex.search(u)]
