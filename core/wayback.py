import subprocess,re,json
from core.others import good,bad,info,requester
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
        '.*\/cgi-bin\/redirect.cgi\?.*',
        '.*\?checkout_url=.*',
        '.*\?image_url=.*',
        '.*\/out\?.*',
        '.*\?continue=.*',
        '.*\?view=.*',
        '.*\/redirect\/.*',
        '.*\?go=.*',
        '.*\?redirect=.*',
        '.*\?URL=.*',
        '.*\?externallink=.*',
        '.*\?nextURL=.*'
        ]

urls = []
matched = []
def get_urls(url, path):

    file = open(path,"w", encoding='utf-8')
    fetcher(url)

    for url in urls:
        match = re.search("|".join(dorks), url)
        try:
            print("%s %s" % (good,match.group()))
        except AttributeError:
            print("%s No juicy URLs found" % bad)
            return
        matched.append(match.group()) 

    if len(matched) > 0:
        for matches in matched:
            file.write("{}\n".format(matches))

    else:
        print("%s No juicy URLs found" % bad)

def fetcher(url):
        todate = datetime.date.today().year
        fromdate = todate - 2
        result = requester("https://web.archive.org/cdx/search/cdx?url=%s*&output=json&collapse=urlkey&filter=statuscode:200&limit=200from=%d&to=%d" % (url, fromdate, todate), False)
        jsonOutput = json.loads(result.text)

        for output in range(1, 101, 1):
            urls.append(jsonOutput[output][2])