"""HTTP client for Oralyzer with configurable proxy and timeouts."""

import logging
import threading
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
)


class HttpClient:
    """HTTP client with connection pooling and retry logic.

    Thread-safe: each thread gets its own session to avoid cookie leakage.
    """

    def __init__(
        self,
        proxy: Optional[str] = None,
        timeout: int = 10,
        user_agent: str = DEFAULT_USER_AGENT,
    ):
        self.timeout = timeout
        self.proxy = proxy
        self.user_agent = user_agent
        self._local = threading.local()

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        session.headers.update({"User-Agent": self.user_agent})

        retry_strategy = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=10, pool_maxsize=10)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        return session

    @property
    def session(self) -> requests.Session:
        """Get thread-local session."""
        if not hasattr(self._local, "session"):
            self._local.session = self._create_session()
        return self._local.session  # type: ignore[no-any-return]

    def get(
        self,
        url: str,
        params: Optional[dict] = None,
        allow_redirects: bool = False,
    ) -> requests.Response:
        """Send GET request without following redirects by default."""
        proxies = {"http": self.proxy, "https": self.proxy} if self.proxy else None

        return self.session.get(
            url,
            params=params,
            allow_redirects=allow_redirects,
            proxies=proxies,
            timeout=self.timeout,
            verify=True,
        )
