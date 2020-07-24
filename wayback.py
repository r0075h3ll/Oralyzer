import subprocess,re

dorks = [
        '.*\?next=',
        '.*\?url=',
        '.*\?target=',
        '.*\?rurl=',
        '.*\/dest=',
        '.*\/destination',
        '.*\?redir=',
        '.*\?redirect_uri=',
        '.*\?return=',
        '.*\?return_path',
        '.*\/cgi-bin\/redirect.cgi?',
        '.*\?checkout_url=',
        '.*\?image_url=',
        '.*\/out\?',
        '.*\?continue=',
        '.*\?view=',
        '.*\/redirect\/',
        '.*\?go=',
        '.*\?redirect=',
        '.*\?URL=',
        '.*\?externallink='
        ]

urls = []
matched = []
def get_urls(url, path):

    file = open(path,"w")
    no_output = subprocess.run(['waybackurls', url], capture_output=True, text=True)
    urls.append(no_output.stdout)
    for url in urls:
        match = re.search("|".join(dorks), url)
        print("{} {}".format("[\033[92m•\033[00m]", match.group()))
        matched.append(match.group())

    if len(matched) > 0:
        for matches in matched:
            file.write("{}\n".format(matches))

    else:
        print("{} No juicy URLs found".format("[\033[91m•\033[99m]"))
