#!/usr/bin/env python3
#https://twitter.com/0xNanda
good = "[\033[92m•\033[00m]" 
bad = "[\033[91m•\033[00m]"
info = "[\033[93m•\033[00m]"
hue = '\033[1mHeuristics\033[00m:'
print("\n\t\033[3mOralyzer\033[00m \033[1m{\033[00m\033[1m\033[92mOpen Redirection Analyzer\033[00m\033[00m\033[1m}\033[00m\n")

#---------------------------------------------------------#

import argparse,os,re,random
from core.wayback import *
from bs4 import BeautifulSoup
try:
        from urllib.parse import *
except ImportError:
        print("%s Oralyzer requires atleast Python 3.6.x to run." % bad)
        exit()
import requests
#----------------------------------------------------------------------------------#

parser = argparse.ArgumentParser()
parser.add_argument('-u', '--url', help='target', dest="url")
parser.add_argument('-f', '--file', help='scan multiple targets', dest='path')
parser.add_argument('-p', '--proxy', help='use proxy', dest='proxy')
parser.add_argument('-w', '--wayback', help='use wayback to fetch juicy urls', action="store_true", dest='waybacks')
parser.add_argument('-o', '--output', help='store the urls found by wayback', dest='output')
args = parser.parse_args()
url = args.url
path = args.path
proxy = args.proxy
waybacks = args.waybacks
output = args.output
#-------------------------------------------------------#

if args.url==None and args.path==None:
    print('Made with \033[91m<3\033[00m by 0xNanda')
    parser.print_help()
    exit()

user = ['Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36 OPR/43.0.2442.991',
'Mozilla/5.0 (Linux; U; Android 4.2.2; en-us; A1-810 Build/JDQ39) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Safari/534.30',
'Mozilla/5.0 (Windows NT 5.1; rv:52.0) Gecko/20100101 Firefox/52.0',
'Mozilla/5.0 (PLAYSTATION 3 4.81) AppleWebKit/531.22.8 (KHTML, like Gecko)',
'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36 OPR/48.0.2685.52',
'Mozilla/5.0 (SMART-TV; X11; Linux armv7l) AppleWebKit/537.42 (KHTML, like Gecko) Chromium/25.0.1349.2 Chrome/25.0.1349.2 Safari/537.42',
'Mozilla/5.0 (Windows NT 6.0; WOW64; Trident/7.0; rv:11.0) like Gecko',
'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/601.2.7 (KHTML, like Gecko)',
'Mozilla/5.0 (PlayStation 4 5.01) AppleWebKit/601.2 (KHTML, like Gecko)']

proxies = { "http": proxy, "https": proxy }
#-------------------------------------------------------#

def analyze(url):
    http = urlsplit(url).scheme
    if http==False:
        url = 'http://'+url
    if http==True:
        if http=='https':
            url = url.replace('https','http')
    parameter = '=' in url
    if parameter:
        if url.endswith('=')==False:
            print("%s Omit the value of parameter that you wanna fuzz" % info)
            exit()
    elif parameter==False:
        if url.endswith('/')==True:
            pass
        elif url.endswith('/')==False:
            print('%s Appending payloads just after the URL' % info)
            url = url+'/'
    print('%s Infusing payloads' % info)
    file = open('payloads.txt','r')
    urls = []
    redirect_codes = [i for i in range(300,311,1)]

#-----------------------------------------------------------------#
    

    for payload in file:
        urls.append(url+payload.rstrip('\n'))
 
    for uri in urls:
        header = {'User-Agent': random.choice(user)}
        if args.proxy:
            try:
                page = requests.get(uri, allow_redirects=False, headers=header, proxies=proxies, timeout=40)
            except requests.exceptions.Timeout:
                print("{} \033[1mTimeout\033[00m: {}".format(bad, uri))
                continue
            except requests.exceptions.ConnectionError:
                print("{} \033[1mConnection Error\033[00m".format(bad))
                break
        else:
            try:
                page = requests.get(uri, allow_redirects=False, headers=header, timeout=15)
            except requests.exceptions.Timeout:
                print("{} \033[1mTimeout\033[00m: {}".format(bad, uri))
                continue
            except requests.exceptions.ConnectionError:
                print("{} \033[1mConnection Error\033[00m".format(bad))
                break

        soup = BeautifulSoup(page.text,'html.parser')
        location = 'window.location' in str(soup.find_all('script'))
        href = 'location.href' in str(soup.find_all('script'))
        google = 'http://www.google.com' in str(soup.find_all('script'))
        metas = str(soup.find_all('meta'))
        meta_tag_search = "http://www.google.com" in metas
#----------------------------------------------------------------------------------------------#
        if page.status_code in redirect_codes:
            if meta_tag_search and "http-equiv=\"refresh\"" in metas:
                print("%s Meta Tag Redirection" % good)
                break
            else:
                print("%s %s Header Based Redirection : %s -> \033[92m%s\033[00m" % (good, hue, uri, page.headers['Location']))
            
        elif page.status_code==200:
            if google:
#---------------------------------------------------------------------------------------------_#
                print("%s %s Javascript Based Redirection" % (good,hue))
                if location and href:
                    print("%s Vulnerable Sink Found: \033[91mwindow.location\033[00m" % (good))
                    print("%s Vulnerable Sink Found: \033[91mlocation.href\033[00m" % (good))
                elif href:
                    print("%s Vulnerable Sink Found: \033[91mlocation.href\033[00m" % (good))
                elif location:
                    print("%s Vulnerable Sink Found: \033[91mwindow.location\033[00m" % (good))
                print("%s Try fuzzing it for DOM XSS or Visit: \033[92m%s\033[00m or \033[92m%s\033[00m" % (info,url+'javascript:alert(1)', url+'"><img src=1 onerror=alert(1) />'))
                break

            elif location and google==None:
                print("%s Vulnerable Sink Found: \033[91mwindow.location\033[00m" % (good))
                print("%s Try fuzzing it for DOM XSS or Visit: \033[92m%s\033[00m or \033[92m%s\033[00m o" % (info,url+'"><img src=1 onerror=alert(1) />',url+'javascript:alert(1)'))
                break
#------------------------------------------------------------------------------------#
            if meta_tag_search and "http-equiv=\"refresh\"" in str(page.text):
                print("%s Meta Tag Redirection" % good)
                break
            elif "http-equiv=\"refresh\"" in str(page.text) and not meta_tag_search:
                print("%s The page is only getting refreshed" % bad)
                break
#----------------------------------------------------------------------------------------#
        elif page.status_code==404:
            print("%s %s \033[92m\033[1m->\033[00m\033[00m (Not Found)\033[91m404\033[00m" %(bad,uri))
        elif page.status_code==403:
            print("%s %s \033[92m\033[1m->\033[00m\033[00m (Forbidden)\033[91m403\033[00m" % (bad,uri))
        elif page.status_code==400:
            print("%s %s \033[92m->\033[00m (Bad Request)\033[91m400\033[00m" % (bad,uri))
#-------------------------------------------------------------------------------------------------------------------------------#
try:
    if args.waybacks==False and args.url:
        analyze(url)

    elif args.waybacks==False and args.path:
        with open(path, "r") as file:
            for url in file:
                print("%s Target \033[91m~>\033[00m \033[92m%s\033[00m" % (info, url.rstrip('\n')))
                analyze(url.rstrip('\n'))
                print(80*"\033[1m-\033[00m")

    elif args.url and args.waybacks and args.output:
        print("{} Getting juicy URLs with \033[93mwaybackurls\033[00m".format(info))
        get_urls(url, output)

    elif args.path and args.waybacks and args.output:
        print("{} Getting juicy URLs with \033[93mwaybackurls\033[00m".format(info))
        with open(path, "r") as file:
            for url in file:
                print("%s Target \033[91m~>\033[00m \033[92m%s\033[00m" % (info, url.rstrip('\n')))
                get_urls(url.rstrip('\n'), output)
                print(80*"\033[1m-\033[00m")

    else:
        print("{} Filename not specified".format(bad))

except KeyboardInterrupt: 
    print("\n\033[91mQuitting...\033[00m")

#----------------------------------------------------------------------------------------------------------------------------------#
