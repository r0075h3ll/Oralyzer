"""Shared helpers for Oralyzer: HTTP request engine and payload generation."""

import requests
from urllib.parse import parse_qs, urlparse, urlunparse

good = "\033[92m[+]\033[00m"
bad = "\033[91m[-]\033[00m"
info = "\033[93m[!]\033[00m"

header = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36'
}

# Configure the proxy before using --proxy.
proxies = {"http": "http://127.0.0.1:8000", "https": "http://127.0.0.1:8000"}

request = requests.Session()
results = []


def requester(url: str, proxy: bool, parameters: str = "") -> requests.Response:
    """Send a GET request without following redirects.

    Args:
        url: Target URL.
        proxy: Whether to route through the configured proxy.
        parameters: Query parameters to append.

    Returns:
        The response object.
    """
    if proxy:
        return request.get(url, allow_redirects=False, headers=header, proxies=proxies, verify=False, timeout=30, params=parameters)
    return request.get(url, allow_redirects=False, headers=header, timeout=10, verify=False, params=parameters)


def generator(url: str, payloads: list) -> list:
    """Generate regex-bypass variants of each payload using the target host.

    Args:
        url: Target URL whose host is embedded in the variants.
        payloads: Payload strings.

    Returns:
        List of variant payloads.
    """
    root = urlparse(url).netloc
    variants = []
    for payload in payloads:
        variants.append("{}.{}".format(payload, root))
        variants.append("{}/{}".format(payload, root))
    return variants


def multitest(url: str, payloads: list):
    """Build the injected URLs/params for a target and payload list.

    Args:
        url: Target URL.
        payloads: Payload strings.

    Returns:
        A tuple (queries, sent, baseUrl) when the URL has query parameters,
        or a list [urls, sent] when payloads are appended to the path.
    """
    if urlparse(url).scheme == '':
        url = 'http://' + url

    regexBypassPayloads = generator(url, payloads)
    if '=' in url:
        if url.endswith('='):
            url += 'r007'
        parsedQueries = parse_qs(urlparse(url).query)
        keys = [key for key in parsedQueries]
        values = [value for value in parsedQueries.values()]

        parsedUrl = list(urlparse(url))
        parsedUrl[-2] = ''
        baseUrl = urlunparse(parsedUrl)

        queries = []
        sent = []
        count = 0
        for key in keys:
            for payload in payloads:
                parsedQueries[key] = payload
                queries.append(parsedQueries.copy())
                sent.append(payload)

            for payload in regexBypassPayloads:
                parsedQueries[key] = payload
                queries.append(parsedQueries.copy())
                sent.append(payload)

            parsedQueries[key] = values[count]
            count += 1
        return queries, sent, baseUrl

    urls = []
    sent = []
    print('%s Appending payloads just after the URL' % info)
    if not url.endswith('/'):
        url += '/'

    for payload in payloads:
        urls.append(url + payload)
        sent.append(payload)

    for payload in regexBypassPayloads:
        urls.append(url + payload)
        sent.append(payload)
    return [urls, sent]
