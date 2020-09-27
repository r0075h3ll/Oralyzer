#!/usr/bin/env python3
#https://twitter.com/0xNanda
print('''\033[92m   ____           __
  / __ \_______ _/ /_ _____ ___ ____
 / /_/ / __/ _ `/ / // /_ // -_) __/
 \____/_/  \_,_/_/\_, //__/\__/_/
                 /___/
\033[00m''')

#---------------------------------------------------------#

import argparse,re,random
from core.wayback import get_urls
from core.crlf import CrlfScan
from core.others import good,bad,info,requester
from bs4 import BeautifulSoup
try:
        from urllib.parse import urlsplit
except ImportError:
        print("%s Oralyzer requires atleast Python 3.7.x to run." % bad)
        exit()
import requests
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
    print('Made by \033[97m0xNanda\033[00m')
    parser.print_help()
    exit()
#-------------------------------------------------------#

def analyze(url):
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
    print('%s Infusing payloads' % info)
    if args.payload:
        file = open(args.payload,'r')
    else:
        file = open('payloads.txt', 'r')
    urls = []
    redirect_codes = [i for i in range(300,311,1)]

#-----------------------------------------------------------------#

    for payload in file:
        urls.append(url+payload.rstrip('\n'))

    for uri in urls:
        if args.proxy:
            try:
                page = requester(uri,True)
            except requests.exceptions.Timeout:
                print("[\033[91mTimeout\033[00m] %s" % url)
                break
            except requests.exceptions.ConnectionError:
                print("%s Connection Error" % bad)
                break
        else:
            try:
                page = requester(uri,False)
            except requests.exceptions.Timeout:
                print("[\033[91mTimeout\033[00m] %s" % url)
                break
            except requests.exceptions.ConnectionError:
                print("%s Connection Error" % bad)
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
                print("%s Header Based Redirection : %s ▶ \033[92m%s\033[00m" % (good, uri, page.headers['Location']))

        elif page.status_code==200:
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
                break

            elif location and google==None:
                print("%s Vulnerable Source Found: \033[1mwindow.location\033[00m" % good)
                print("%s Try fuzzing the URL for DOM XSS" % info)
                break
#------------------------------------------------------------------------------------#
            if meta_tag_search and "http-equiv=\"refresh\"" in str(page.text):
                print("%s Meta Tag Redirection" % good)
                break
            elif "http-equiv=\"refresh\"" in str(page.text) and not meta_tag_search:
                print("%s The page is only getting refreshed" % bad)
                break


        if page.status_code==404:
            print("[\033[91m404\033[00m] %s" % uri)
        elif page.status_code==403:
            print("[\033[91m403\033[00m] %s" % uri)
        elif page.status_code==400:
            print("[\033[91m400\033[00m] %s" % uri)

#-------------------------------------------------------------------------------------------------------------------------------#
try:
    if args.waybacks==False and args.crlf==False and args.url:
        analyze(url)

    elif args.crlf:

        if args.proxy and args.path:
            uris = []
            with open(path, "r") as file:
                for url in file:
                    uris.append(url)
                for url in uris:
                    print("%s Target: \033[1m\033[92m%s\033[00m\033[00m" % (info, url.rstrip('\n')))
                    CrlfScan(url.rstrip('\n'),True)
                    print(80*"\033[97m—\033[00m")
        elif args.proxy and not args.path:
            CrlfScan(url,True)

        elif args.path and not args.proxy:
            uris = []
            with open(path, "r") as file:
                for url in file:
                    uris.append(url)
                for url in uris:
                    print("%s Target: \033[1m\033[92m%s\033[00m\033[00m" % (info, url.rstrip('\n')))
                    CrlfScan(url.rstrip('\n'),False)
                    print(80*"\033[97m—\033[00m")
        else:
            CrlfScan(url,False)

    elif args.waybacks==False and args.path:
        uris = []
        with open(path, "r") as file:
            for url in file:
                uris.append(url)
            for url in uris:
                print("%s Target: \033[1m\033[92m%s\033[00m\033[00m" % (info, url.rstrip('\n')))
                analyze(url.rstrip('\n'))
                print(80*"\033[97m—\033[00m")

    elif args.url and args.waybacks:
        print("%s Getting juicy URLs with \033[1m\033[93mwaybackurls\033[00m\033[00m" % info)
        try:
            get_urls(url, "wayback_urls.txt")
        except KeyboardInterrupt:
            print("\n\033[91mQuitting...\033[00m")
            exit()

    elif args.path and args.waybacks:
        print("%s Getting juicy URLs with \033[93mwaybackurls\033[00m" % info)
        uris = []
        with open(path, "r") as file:
            for url in file:
                uris.append(url)
            for url in uris:
                print("%s Target: \033[1m\033[92m%s\033[00m\033[00m" % (info, url.rstrip('\n')))
                try:
                    get_urls(url.rstrip('\n'), "wayback_{}.txt".format(random.randint(0,100)))
                    print(80*"\033[97m—\033[00m")
                except KeyboardInterrupt:
                    print("\n\033[91mQuitting...\033[00m")
                    exit()

    else:
        print("%s Filename not specified" % bad)

except KeyboardInterrupt:
    print("\n\033[91mQuitting...\033[00m")
#----------------------------------------------------------------------------------------------------------------------------------#