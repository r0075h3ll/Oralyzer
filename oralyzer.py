#!/usr/bin/env python3
#https://twitter.com/r0075h3ll
print('''\033[92m   ____           __
  / __ \_______ _/ /_ _____ ___ ____
 / /_/ / __/ _ `/ / // /_ // -_) __/
 \____/_/  \_,_/_/\_, //__/\__/_/
                 /___/
\033[00m''')
arrow = '\033[91m➤\033[00m'
#----------------------------------------------------------#
import sys
if sys.version_info.major > 2 and sys.version_info.minor > 6:
    pass
else:
    print("%s Oralyzer requires atleast Python 3.7.x to run." % bad)
    exit()
#---------------------------------------------------------#
import argparse,re,random,warnings,ssl,requests
from core.wayback import get_urls
from core.crlf import CrlfScan
from core.others import good,bad,info,requester,multitest,urlparse
from bs4 import BeautifulSoup
warnings.filterwarnings('ignore')
ssl._create_default_https_context = ssl._create_unverified_context
#----------------------------------------------------------------------------------#
parser = argparse.ArgumentParser()
parser.add_argument('-u', '--url', help='scan single target', dest="url")
parser.add_argument('-l', '--list', help='scan multiple target', dest='path')
parser.add_argument('-crlf', help='scan for CRLF Injection', action='store_true', dest='crlf')
parser.add_argument('-p', '--payload', help='use payloads from a file', dest='payload')
parser.add_argument('--proxy', help='use proxy', action='store_true' , dest='proxy')
parser.add_argument('--wayback', help='fetch URLs from archive.org', action="store_true", dest='waybacks')
args = parser.parse_args()
url = args.url
path = args.path
proxy = args.proxy
#-------------------------------------------------------#
if args.url==None and args.path==None:
    print('Made by \033[97mr0075h3ll\033[00m')
    parser.print_help()
    exit()
#--------------------------------------------------------#
if args.payload:
    FilePath = args.payload
    file = open(FilePath, encoding='utf-8').read().splitlines()
else:
    try:
        FilePath = 'payloads.txt'
        file = open(FilePath, encoding='utf-8').read().splitlines()
    except FileNotFoundError:
        print("%s Payload file not found! Try using '-p' flag to use payload file of your choice" % bad)
        exit()

if args.path:
    UrlList = open(path, encoding='utf-8').read().splitlines()
#-------------------------------------------------------#
def analyze(url):
    if urlparse(url).scheme == '':
        url = 'http://' + url
    global MultiTest
    MultiTest = multitest(url,FilePath)

    print('%s Infusing payloads' % info)
    if type(MultiTest) is tuple:
        for params in MultiTest[0]:
            TestingBreak = request(MultiTest[1],params)
            if TestingBreak:
                break
    else:
        for url in MultiTest:
            TestingBreak = request(url)
            if TestingBreak:
                break
#--------------------------------------------------------#
def request(uri,params='',PayloadIndex=0):
    skip = 1
    if args.proxy:
        try:
            page = requester(uri,True,params)
        except requests.exceptions.Timeout:
            print("[\033[91mTimeout\033[00m] %s" % url)
            return skip
        except requests.exceptions.ConnectionError:
            print("%s Connection Error" % bad)
            return skip
    else:
        try:
            page = requester(uri,False,params)
        except requests.exceptions.Timeout:
            print("[\033[91mTimeout\033[00m] %s" % url)
            return skip
        except requests.exceptions.ConnectionError:
            print("%s Connection Error" % bad)
            return skip
        except IndexError:
            PayloadIndex = 0

    function_break = check(page,page.request.url,file[PayloadIndex])
    PayloadIndex += 1
    if function_break:
        return skip                
#--------------------------------------------------------------------#
def check(PageVar,FinalUrl,payload='http://www.google.com'):
    skip = 1
    RedirectCodes = [i for i in range(300,311,1)]
    soup = BeautifulSoup(PageVar.text,'html.parser')
    location = 'window.location' in str(soup.find_all('script'))
    href = 'location.href' in str(soup.find_all('script'))
    google = payload in str(soup.find_all('script'))
    metas = str(soup.find_all('meta'))
    meta_tag_search = payload in metas
#----------------------------------------------------------------------------------------------#
    if PageVar.status_code in RedirectCodes:
        if meta_tag_search and "http-equiv=\"refresh\"" in metas:
            print("%s Meta Tag Redirection" % good)
            return skip
            
        else:
            print("%s Header Based Redirection : %s %s  \033[92m%s\033[00m" % (good, FinalUrl, arrow,PageVar.headers['Location']))

    elif PageVar.status_code==200:
        if google:
#---------------------------------------------------------------------------------------------_#
            print("%s Javascript Based Redirection" % good)
            if location and href:
                print("%s Vulnerable Source Found: \033[1mwindow.location\033[00m" % good)
                print("%s Vulnerable Source Found: \033[1mlocation.href\033[00m" % good)
            elif href:
                print("%s Vulnerable Source Found: \033[1mlocation.href\033[00m" % good)
            elif location:
                print("%s Vulnerable Source Found: \033[1mwindow.location\033[00m" % good)
            print("%s Try fuzzing the URL for DOM XSS" % info)
            return skip

        elif location:
            if 'window.location = {}'.format(payload):
                print("%s Vulnerable Source Found: \033[1mwindow.location\033[00m" % good)
                print("%s Try fuzzing the URL for DOM XSS" % info)
                return skip
            else:
                print("%s Potentially Vulnerable Source Found: \033[1mwindow.location\033[00m")
#------------------------------------------------------------------------------------#
        if meta_tag_search and "http-equiv=\"refresh\"" in str(PageVar.text):
            print("%s Meta Tag Redirection" % good)
            return skip

        elif "http-equiv=\"refresh\"" in str(PageVar.text) and not meta_tag_search:
            print("%s The page is only getting refreshed" % bad)
            return skip

#-------------------------------------------------------------------------------------#
    elif PageVar.status_code==404:
        print("%s %s [\033[91m404\033[00m]" % (bad,FinalUrl))
    elif PageVar.status_code==403:
        print("%s %s [\033[91m403\033[00m]" % (bad,FinalUrl))
    elif PageVar.status_code==400:
        print("%s %s [\033[91m400\033[00m]" % (bad,FinalUrl))

    else:
        print("%s Found nothing :: %s" % (bad,FinalUrl))

#-------------------------------------------------------------------------------------------------------------------------------#
try:
    if args.waybacks==False and args.crlf==False and args.url:
        analyze(url)

    elif args.crlf:
        if args.proxy and args.path:
            for url in UrlList:
                print("%s Target: \033[92m%s\033[00m" % (info, url))
                CrlfScan(url,True)
                print(80*"\033[97m—\033[00m")
        elif args.proxy and not args.path:
            CrlfScan(url,True)

        elif args.path and not args.proxy:
            for url in UrlList:
                print("%s Target: \033[92m%s\033[00m" % (info, url))
                CrlfScan(url,False)
                print(80*"\033[97m—\033[00m")
        else:
            CrlfScan(url,False)

    elif args.waybacks==False and args.path:
        for url in UrlList:
            print("%s Target: \033[92m%s\033[00m" % (info, url))
            analyze(url)
            print(80*"\033[97m—\033[00m")

    elif args.url and args.waybacks:
        print("%s Getting juicy URLs with \033[1m\033[93mwaybackurls\033[00m\033[00m" % info)
        get_urls(url, "wayback_urls.txt")

    elif args.path and args.waybacks:
        print("%s Getting juicy URLs with \033[93mwaybackurls\033[00m" % info)
        for url in UrlList:
            print("%s Target: \033[92m%s\033[00m" % (info, url))
            get_urls(url, "wayback_{}.txt".format(random.randint(0,100)))
            print(80*"\033[97m—\033[00m")

    else:
        print("%s Filename not specified" % bad)

except KeyboardInterrupt:
    print("\n\033[91mQuitting...\033[00m")
    exit()