good = "\033[92m[+]\033[00m"
bad = "\033[91m[-]\033[00m"
info = "\033[93m[!]\033[00m"

import requests,random
from urllib.parse import parse_qs,urlparse,urlunparse
import re
user = ['Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36 OPR/43.0.2442.991',
'Mozilla/5.0 (Linux; U; Android 4.2.2; en-us; A1-810 Build/JDQ39) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Safari/534.30',
'Mozilla/5.0 (Windows NT 5.1; rv:52.0) Gecko/20100101 Firefox/52.0',
'Mozilla/5.0 (PLAYSTATION 3 4.81) AppleWebKit/531.22.8 (KHTML, like Gecko)',
'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36 OPR/48.0.2685.52',
'Mozilla/5.0 (SMART-TV; X11; Linux armv7l) AppleWebKit/537.42 (KHTML, like Gecko) Chromium/25.0.1349.2 Chrome/25.0.1349.2 Safari/537.42',
'Mozilla/5.0 (Windows NT 6.0; WOW64; Trident/7.0; rv:11.0) like Gecko',
'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/601.2.7 (KHTML, like Gecko)',
'Mozilla/5.0 (PlayStation 4 5.01) AppleWebKit/601.2 (KHTML, like Gecko)']

header = {'User-Agent': random.choice(user)}
proxies = {"http":"http://127.0.0.1:8000", "https":"http://127.0.0.1:8000" } #configure the proxy before using
request = requests.Session()

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
        count = 0
        for key in keys:
            for payload in payloads:
                parsedQueries[key] = payload
                queries.append(parsedQueries.copy())

            for payload in regexBypassPayloads:
                parsedQueries[key] = payload
                queries.append(parsedQueries.copy())

            parsedQueries[key] = values[count]
            count += 1
        return queries,finalURL
    else:
        urls = []
        print('%s Appending payloads just after the URL' % info)
        if not url.endswith('/'):
            url += '/'
            
        for payload in payloads:
            urls.append(url+payload)

        for payload in regexBypassPayloads:
            urls.append(url+payload)
        return urls