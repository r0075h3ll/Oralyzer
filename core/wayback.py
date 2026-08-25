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

def fetcher(url):
        #----------------------wayback-------------------------#
        todate = datetime.date.today().year
        fromdate = todate - 2
        result = requester("https://web.archive.org/cdx/search/cdx?url=%s*&output=json&collapse=urlkey&filter=statuscode:200&limit=1000from=%d&to=%d" % (url, fromdate, todate), False)
        jsonOutput = json.loads(result.text)


        for output in range(1, min(len(jsonOutput), 1000), 1):
            urls.append(unquote(jsonOutput[output][2]))