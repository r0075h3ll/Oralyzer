import subprocess,re
from core.others import good,bad,info

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
    try:
        no_output = subprocess.run(['waybackurls', url], capture_output=True, text=True)
    except FileNotFoundError:
        print("%s waybackurls not found" % bad)
        exit()
    urls.append(no_output.stdout)
    for url in urls:
        match = re.search("|".join(dorks), url)
        try:
            print("%s %s" % (good,match.group()))
        except AttributeError:
            print("%s No juicy URLs found" % bad)
            exit()
        matched.append(match.group()) 

    if len(matched) > 0:
        for matches in matched:
            file.write("{}\n".format(matches))

    else:
        print("%s No juicy URLs found" % bad)