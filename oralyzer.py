#!/usr/bin/env python3
#https://twitter.com/r0075h3ll
print("\033[91m\n\tOralyzer\033[00m\n")
arrow = '\033[91m->\033[00m'
#----------------------------------------------------------#
import sys
if sys.version_info.major > 2 and sys.version_info.minor > 6:
    pass
else:
    print("%s Oralyzer requires atleast Python 3.7.x to run." % bad)
    exit()
#---------------------------------------------------------#
import argparse,re,random,warnings,ssl,requests,os
from core.wayback import getURLs
from core.crlf import crlfScan
from core.others import good,bad,info,requester,multitest,urlparse
from bs4 import BeautifulSoup
warnings.filterwarnings('ignore')
ssl._create_default_https_context = ssl._create_unverified_context
#----------------------------------------------------------------------------------#
parser = argparse.ArgumentParser()
parser.add_argument('-u', help='scan single target', dest="url")
parser.add_argument('-o', help='export path', dest="export")
parser.add_argument('-l', help='scan multiple targets from a file', dest='path')
parser.add_argument('-crlf', help='scan for CRLF Injection', action='store_true', dest='crlf')
parser.add_argument('-p', help='use payloads from a file', dest="payload", default="payloads.txt")
parser.add_argument('--proxy', help='use proxy', action='store_true' , dest='proxy')
parser.add_argument('--wayback', help='fetch URLs from archive.org', action="store_true", dest='waybacks')
args = parser.parse_args()
url = args.url

if ((args.payload != "payloads.txt") and (args.crlf or args.waybacks)): print("%s '-p' can't be used with '-crlf' or '--wayback'" % bad), exit()
#-------------------------------------------------------#
if not (args.url or args.path):
    print('Made by \033[1mr0075h3ll\033[00m')
    print(parser.format_help().lower())
#--------------------------------------------------------#
if not args.crlf and not args.waybacks:
    try:
        file = open(args.payload, encoding='utf-8').read().splitlines()
    except FileNotFoundError:
        print("%s Payload file not found" % bad)
        exit()

if args.path:
    try:
        urls = open(args.path, encoding='utf-8').read().splitlines()
    except FileNotFoundError: print("%s Target file not found" % bad), exit()
#-------------------------------------------------------#
if args.export:
    if os.path.exists(args.export):
        open(args.export, 'w').close() # erase the content of the file
    outputFile = open(args.export, "a+")
else:
    outputFile = None

def analyze(url):
    multiTestCall = multitest(url,file)

    print('%s Infusing payloads' % info)
    if outputFile is not None:
        outputFile.write('Infusing payloads\n')

    if type(multiTestCall) == tuple:
        for params in multiTestCall[0]:
            testingBreak = request(multiTestCall[1],params)
            if testingBreak:
                break
    else:
        for url in multiTestCall:
            testingBreak = request(url)
            if testingBreak:
                break
#--------------------------------------------------------#
def request(URI,params=''):
    try:
        page = requester(URI,args.proxy,params)
    except requests.exceptions.Timeout:
        print("[\033[91mTimeout\033[00m] %s" % url)
        return True
    except requests.exceptions.ConnectionError:
        print("%s Connection Error" % bad)
        return True

    funcBreak = check(page, page.request.url)
    if funcBreak:
        return True                
#--------------------------------------------------------------------#
def check(respOBJ,finalURL):
    payload = "|".join([re.escape(i) for i in file])
    redirectCodes = [red for red in range(300,311,1)]
    errorCodes = [error for error in range(400, 411, 1)]
    soup = BeautifulSoup(respOBJ.text,'html.parser')
    google = re.search(payload, str(soup.find_all("script")), re.IGNORECASE)
    metas = str(soup.find_all('meta'))
    metaTagSearch = re.search(payload, metas, re.IGNORECASE)

    sourcesSinks = [  
                "location.href",
                "location.hash",
                "location.search",
                "location.pathname",
                "document.URL",
                "window.name",
                "document.referrer",
                "document.documentURI",
                "document.baseURI",
                "document.cookie",
                "location.hostname",
                "jQuery.globalEval",
                "eval",
                "Function",
                "execScript",
                "setTimeout",
                "setInterval",
                "setImmediate",
                "msSetImmediate",
                "script.src",
                "script.textContent",
                "script.text",
                "script.innerText",
                "script.innerHTML",
                "script.appendChild",
                "script.append",
                "document.write",
                "document.writeln",
                "jQuery",
                "jQuery.$",
                "jQuery.constructor",
                "jQuery.parseHTML",
                "jQuery.has",
                "jQuery.init",
                "jQuery.index",
                "jQuery.add",
                "jQuery.append",
                "jQuery.appendTo",
                "jQuery.after",
                "jQuery.insertAfter",
                "jQuery.before",
                "jQuery.insertBefore",
                "jQuery.html",
                "jQuery.prepend",
                "jQuery.prependTo",
                "jQuery.replaceWith",
                "jQuery.replaceAll",
                "jQuery.wrap",
                "jQuery.wrapAll",
                "jQuery.wrapInner",
                "jQuery.prop.innerHTML",
                "jQuery.prop.outerHTML",
                "element.innerHTML",
                "element.outerHTML",
                "element.insertAdjacentHTML",
                "iframe.srcdoc",
                "location.replace",
                "location.assign",
                "window.open",
                "iframe.src",
                "javascriptURL",
                "jQuery.attr.onclick",
                "jQuery.attr.onmouseover",
                "jQuery.attr.onmousedown",
                "jQuery.attr.onmouseup",
                "jQuery.attr.onkeydown",
                "jQuery.attr.onkeypress",
                "jQuery.attr.onkeyup",
                "element.setAttribute.onclick",
                "element.setAttribute.onmouseover",
                "element.setAttribute.onmousedown",
                "element.setAttribute.onmouseup",
                "element.setAttribute.onkeydown",
                "element.setAttribute.onkeypress",
                "element.setAttribute.onkeyup",
                "createContextualFragment",
                "document.implementation.createHTMLDocument",
                "xhr.open",
                "xhr.send",
                "fetch",
                "fetch.body",
                "xhr.setRequestHeader.name",
                "xhr.setRequestHeader.value",
                "jQuery.attr.href",
                "jQuery.attr.src",
                "jQuery.attr.data",
                "jQuery.attr.action",
                "jQuery.attr.formaction",
                "jQuery.prop.href",
                "jQuery.prop.src",
                "jQuery.prop.data",
                "jQuery.prop.action",
                "jQuery.prop.formaction",
                "form.action",
                "input.formaction",
                "button.formaction",
                "button.value",
                "element.setAttribute.href",
                "element.setAttribute.src",
                "element.setAttribute.data",
                "element.setAttribute.action",
                "element.setAttribute.formaction",
                "webdatabase.executeSql",
                "document.domain",
                "history.pushState",
                "history.replaceState",
                "xhr.setRequestHeader",
                "websocket",
                "anchor.href",
                "anchor.target",
                "JSON.parse",
                "localStorage.setItem.name",
                "localStorage.setItem.value",
                "sessionStorage.setItem.name",
                "sessionStorage.setItem.value",
                "element.outerText",
                "element.innerText",
                "element.textContent",
                "element.style.cssText",
                "RegExp",
                "location.protocol",
                "location.host",
                "input.value",
                "input.type",
                "document.evaluate"
            ]
    escapedSourcesSinks = [re.escape(SnS) for SnS in sourcesSinks]
    sourcesMatch = list(dict.fromkeys(re.findall("|".join(escapedSourcesSinks), str(soup))))
#----------------------------------------------------------------------------------------------#
    if respOBJ.status_code in redirectCodes:
        if metaTagSearch and "http-equiv=\"refresh\"" in metas:
            print("%s Meta Tag Redirection" % good)
            if outputFile is not None:
                outputFile.write("%s Meta Tag Redirection\n" % "[+]")
            return True
            
        else:
            print("%s Header Based Redirection : %s %s  %s" % (good,finalURL,arrow,respOBJ.headers['Location']))
            if outputFile is not None:
                outputFile.write("%s Header Based Redirection : %s %s  %s\n" % ("[+]",finalURL,"->",respOBJ.headers['Location']))

    elif respOBJ.status_code==200:
        if google:
#---------------------------------------------------------------------------------------------#
            print("%s Javascript Based Redirection" % good)
            if outputFile is not None:
                outputFile.write("%s Javascript Based Redirection\n" % "[+]")

            if sourcesMatch != None:
                print("%s Potentially Vulnerable Source/Sink(s) Found: \033[1m%s\033[00m" % (good, " ".join(sourcesMatch)))
                if outputFile is not None:
                    outputFile.write("%s Potentially Vulnerable Source/Sink(s) Found: \033[1m%s\033[00m\n" % ("[+]", " ".join(sourcesMatch)))
            return True

#------------------------------------------------------------------------------------#
        if metaTagSearch and "http-equiv=\"refresh\"" in str(respOBJ.text):
            print("%s Meta Tag Redirection" % good)
            if outputFile is not None:
                outputFile.write("%s Meta Tag Redirection\n" % "[+]")
            return True

        elif "http-equiv=\"refresh\"" in str(respOBJ.text) and not metaTagSearch:
            print("%s The page is only getting refreshed" % bad)
            if outputFile is not None:
                outputFile.write("%s The page is only getting refreshed\n" % "[-]")
            return True

#-------------------------------------------------------------------------------------#
    elif respOBJ.status_code in errorCodes:
        print("%s %s [\033[91m%s\033[00m]" % (bad,finalURL,respOBJ.status_code))
        if outputFile is not None:
            outputFile.write("%s %s %s\n" % ("[-]",finalURL,respOBJ.status_code))

    else:
        print("%s Found nothing :: %s" % (bad,finalURL))
        if outputFile is not None:
            outputFile.write("%s Found nothing :: %s\n" % ("[-]",finalURL))

#-------------------------------------------------------------------------------------------------------------------------------#
try:
    if args.url:
        if args.crlf and not args.waybacks:
            crlfScan(url, args.proxy)

        elif args.waybacks and not args.crlf:
            print("%s Getting juicy URLs from archive.org" % info)
            getURLs(url, "wayback_data.txt")

        elif not (args.crlf and args.waybacks):
            analyze(url)
    
    elif args.path:
        if args.crlf and not args.waybacks:
            for url in urls:
                print("%s Target: %s" % (info, url))
                crlfScan(url,args.proxy)
                print("\n")

        elif args.waybacks and not args.crlf:
            print("%s Getting juicy URLs from archive.org" % info)
            for url in urls:
                print("%s URL: %s" % (info, url))
                getURLs(url, "wayback_%d.txt" % random.randint(0,1000))
                print("\n")

        elif not (args.crlf and args.waybacks):
            for url in urls:
                print("%s Target: \033[92m%s\033[00m" % (info, url))
                analyze(url)
                print("\n")

    if outputFile is not None:
        if not outputFile.closed:
            outputFile.close()

except KeyboardInterrupt:
    print("\nQuitting...")
    if outputFile is not None:
        if not outputFile.closed:
            outputFile.close()
    exit()
