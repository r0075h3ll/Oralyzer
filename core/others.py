good = "\033[92m[+]\033[00m"
bad = "\033[91m[-]\033[00m"
info = "\033[93m[!]\033[00m"

import requests
from urllib.parse import parse_qs,urlparse,urlunparse
header = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36'}
proxies = {"http":"http://127.0.0.1:8000", "https":"http://127.0.0.1:8000" } #configure the proxy before using
request = requests.Session()
results = []

def requester(url,proxy,parameters=''):
    if proxy:
        webOBJ = request.get(url, allow_redirects=False, headers=header, proxies=proxies, verify=False ,timeout=30, params=parameters)
    else:
        webOBJ = request.get(url, allow_redirects=False, headers=header, timeout=10, verify=False, params=parameters)

    return webOBJ

def generator(url,payloads):
    root = urlparse(url).netloc
    regPay = []
    for payload in payloads:
        regPay.append("{}.{}".format(payload,root))
        regPay.append("{}/{}".format(payload,root))
    return regPay

def multitest(url,payloads):
    if urlparse(url).scheme == '': url = 'http://' + url

    regexBypassPayloads = generator(url,payloads)
    if '=' in url:
        if url.endswith('='): url += 'r007'
        parsedQueries = parse_qs(urlparse(url).query)
        keys = [key for key in parsedQueries]
        values = [value for value in parsedQueries.values()]

        parsedURL = list(urlparse(url))
        parsedURL[-2] = ''
        finalURL = urlunparse(parsedURL)

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
        return queries,sent,finalURL
    else:
        urls = []
        sent = []
        print('%s Appending payloads just after the URL' % info)
        if not url.endswith('/'):
            url += '/'

        for payload in payloads:
            urls.append(url+payload)
            sent.append(payload)

        for payload in regexBypassPayloads:
            urls.append(url+payload)
            sent.append(payload)
        return [urls,sent]