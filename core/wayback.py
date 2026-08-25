import subprocess,re,json
from core.others import good,bad,info,requester
from urllib.parse import unquote
import datetime

dorks = [
            '.*\?next=.*',
            '.*\?url=.*',
            '.*\?target=.*',
            '.*\?rurl=.*',
            '.*\/dest=.*',
            '.*\/destination=.*',
            '.*\?redir=.*',
            '.*\?redirect_uri=.*',
            '.*\?return=.*',
            '.*\?return_path.*',
            '.*\/cgi-bin\/redirect\.cgi\?.*',
            '.*\?checkout_url=.*',
            '.*\?image_url=.*',
            '.*\/out\?.*',
            '.*\?continue=.*',
            '.*\?view=.*',
            '.*\/redirect\/.*',
            '.*\?go=.*',
            '.*\?redirect=.*',
            '.*\?externallink=.*',
            '.*\?nextURL=.*'
        ]

urls = []
matchedURLs = []
def getURLs(url, path):

    file = open(path,"w", encoding='utf-8')
    urls.clear()
    matchedURLs.clear()
    fetcher(url)

    for url in urls:
        match = re.search("|".join(dorks), url, re.IGNORECASE)
        try:
            print("%s %s" % (good,match.group()))
            matchedURLs.append(match.group())
        except AttributeError:
            continue

    if len(matchedURLs) > 0:
        for matches in matchedURLs:
            file.write("{}\n".format(matches))

    else:
        print("%s No juicy URLs found" % bad)

    return list(matchedURLs)

def fetcher(url):
        #----------------------wayback-------------------------#
        todate = datetime.date.today().year
        fromdate = todate - 2
        # Query the CDX API for the last two years of snapshots, collapsed by urlkey.
        result = requester("https://web.archive.org/cdx/search/cdx?url=%s*&output=json&collapse=urlkey&filter=statuscode:200&limit=1000&from=%d&to=%d" % (url, fromdate, todate), False)
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
        # that are too short to index safely.
        for row in jsonOutput[1:1000]:
            if isinstance(row, list) and len(row) > 2:
                urls.append(unquote(row[2]))