"""Wayback Machine CDX URL discovery for Oralyzer."""

import datetime
import json
import re

import requests
from urllib.parse import unquote

from core.others import good, bad, info, requester

dorks = [
    r'.*\?next=.*',
    r'.*\?url=.*',
    r'.*\?target=.*',
    r'.*\?rurl=.*',
    r'.*\/dest=.*',
    r'.*\/destination=.*',
    r'.*\?redir=.*',
    r'.*\?redirect_uri=.*',
    r'.*\?return=.*',
    r'.*\?return_path.*',
    r'.*\/cgi-bin\/redirect\.cgi\?.*',
    r'.*\?checkout_url=.*',
    r'.*\?image_url=.*',
    r'.*\/out\?.*',
    r'.*\?continue=.*',
    r'.*\?view=.*',
    r'.*\/redirect\/.*',
    r'.*\?go=.*',
    r'.*\?redirect=.*',
    r'.*\?externallink=.*',
    r'.*\?nextURL=.*'
]

urls = []
matchedUrls = []


def getUrls(url: str, path: str) -> list:
    """Fetch candidate URLs from the CDX API and return dork matches.

    Args:
        url: Target URL to search for on the Wayback Machine.
        path: File to write matched URLs to.

    Returns:
        List of URLs matching the dork patterns.
    """
    urls.clear()
    matchedUrls.clear()
    fetcher(url)

    for url in urls:
        match = re.search("|".join(dorks), url, re.IGNORECASE)
        try:
            print("%s %s" % (good, match.group()))
            matchedUrls.append(match.group())
        except AttributeError:
            continue

    with open(path, "w", encoding='utf-8') as outFile:
        if matchedUrls:
            for match in matchedUrls:
                outFile.write("{}\n".format(match))
        else:
            print("%s No juicy URLs found" % bad)

    return list(matchedUrls)


def fetcher(url: str) -> None:
    """Query the CDX API for the last two years of snapshots, collapsed by urlkey."""
    toDate = datetime.date.today().year
    fromDate = toDate - 2

    # A dropped connection or timeout should read as "no results", not a crash.
    try:
        result = requester("https://web.archive.org/cdx/search/cdx?url=%s*&output=json&collapse=urlkey&filter=statuscode:200&limit=1000&from=%d&to=%d" % (url, fromDate, toDate), False)
    except requests.exceptions.RequestException:
        return

    # The CDX endpoint returns non-JSON (error page, rate-limit notice) on
    # failure, so treat a decode error as an empty result instead of crashing.
    try:
        jsonOutput = json.loads(result.text)
    except ValueError:
        return

    # A successful response is a list of rows; anything else means the query failed.
    if not isinstance(jsonOutput, list):
        return

    # Row 0 is the column header. Row 2 holds the "original" URL; skip rows
    # that are too short or non-string to index and unquote safely.
    for row in jsonOutput[1:1001]:
        if isinstance(row, list) and len(row) > 2 and isinstance(row[2], str):
            urls.append(unquote(row[2]))
