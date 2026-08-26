"""Common Crawl index URL discovery for Oralyzer.

Originally queried the Wayback Machine's CDX API, but web.archive.org
frequently times out or hangs on wildcard domain queries. Common Crawl's
CDX-compatible index (index.commoncrawl.org) serves the same kind of
"every URL we've seen under this domain" query, reliably.
"""

import json
import logging
import re
from typing import List

import requests

from .http import HttpClient

COLLECTIONS_URL = "https://index.commoncrawl.org/collinfo.json"

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
    """Client for querying Common Crawl's CDX-compatible URL index."""

    def __init__(self, http_client: HttpClient):
        self.http_client = http_client
        self._dork_regex = re.compile("|".join(DORKS), re.IGNORECASE)

    def _latest_index_url(self) -> str:
        """Look up the cdx-api URL for the most recent Common Crawl collection."""
        response = self.http_client.get(COLLECTIONS_URL)
        collections = response.json()
        cdx_api: str = collections[0]["cdx-api"]
        return cdx_api

    def fetch_urls(self, url: str) -> List[str]:
        """Query the latest Common Crawl index for URLs under this domain.

        ponytail: only the single most recent collection is queried (a few
        weeks of crawl data), not Wayback's old multi-year window. Loop over
        more of collinfo.json's entries here if deeper history is needed.
        """
        try:
            cdx_api = self._latest_index_url()
        except (requests.exceptions.RequestException, ValueError, KeyError, IndexError):
            logger.warning("Failed to fetch Common Crawl collection list")
            return []

        cc_url = f"{cdx_api}?url={url}*&output=json&filter=status:200&limit=1000"

        try:
            response = self.http_client.get(cc_url)
        except requests.exceptions.RequestException:
            logger.warning("Failed to fetch from Common Crawl index")
            return []

        urls = []
        for line in response.text.splitlines()[:1000]:
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict) and isinstance(row.get("url"), str):
                urls.append(row["url"])

        return urls

    def get_matching_urls(self, url: str) -> List[str]:
        """Fetch URLs and filter by dork patterns."""
        return [u for u in self.fetch_urls(url) if self._dork_regex.search(u)]
