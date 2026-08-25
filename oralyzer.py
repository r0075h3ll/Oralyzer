#!/usr/bin/env python3
# https://twitter.com/r0075h3ll

import argparse
import json
import os
import random
import re
import ssl
import warnings

import requests
from bs4 import BeautifulSoup

from core.wayback import getUrls
from core.crlf import crlfScan
from core.others import good, bad, info, requester, multitest, results

warnings.filterwarnings('ignore')
ssl._create_default_https_context = ssl._create_unverified_context

arrow = '\033[91m->\033[00m'
DEFAULT_PAYLOAD = os.path.join(os.path.dirname(os.path.realpath(__file__)), "core", "payloads.txt")

parser = argparse.ArgumentParser()
parser.add_argument('-u', help='scan single target', dest="url")
parser.add_argument('-o', help='export path', dest="export")
parser.add_argument('-l', help='scan multiple targets from a file', dest='path')
parser.add_argument('-crlf', help='scan for CRLF Injection', action='store_true', dest='crlf')
parser.add_argument('-p', help='use payloads from a file', dest="payload", default=DEFAULT_PAYLOAD)
parser.add_argument('--proxy', help='use proxy', action='store_true', dest='proxy')
parser.add_argument('--wayback', help='fetch URLs from archive.org', action="store_true", dest='waybacks')


def analyze(url: str) -> None:
    """Inject payloads into the target and test each generated URL/params."""
    multiTestCall = multitest(url, payloadLines)

    print('%s Infusing payloads' % info)

    if isinstance(multiTestCall, tuple):
        queries, sent, base = multiTestCall
        for params, payload in zip(queries, sent):
            if request(base, params, payload):
                break
    else:
        urls, sent = multiTestCall
        for url, payload in zip(urls, sent):
            if request(url, '', payload):
                break


def request(uri: str, params: str = "", payload: str = "") -> bool:
    """Fetch a single injected URL and check the response for a redirect."""
    try:
        response = requester(uri, args.proxy, params)
    except requests.exceptions.Timeout:
        print("[\033[91mTimeout\033[00m] %s" % uri)
        return True
    except requests.exceptions.ConnectionError:
        print("%s Connection Error" % bad)
        return True

    return bool(checkResponse(response, response.request.url, payload))


def checkResponse(response: requests.Response, finalUrl: str, payload: str = "") -> bool | None:
    """Detect header/meta/javascript open redirects in a response."""
    payloadRegex = "|".join([re.escape(i) for i in payloadLines])
    redirectCodes = range(300, 311)
    errorCodes = range(400, 411)
    soup = BeautifulSoup(response.text, 'html.parser')
    scriptMatch = re.search(payloadRegex, str(soup.find_all("script")), re.IGNORECASE)
    metaTags = str(soup.find_all('meta'))
    metaTagSearch = re.search(payloadRegex, metaTags, re.IGNORECASE)

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
    escapedSourcesSinks = [re.escape(sink) for sink in sourcesSinks]
    sourcesMatch = list(dict.fromkeys(re.findall("|".join(escapedSourcesSinks), str(soup))))

    if response.status_code in redirectCodes:
        if metaTagSearch and "http-equiv=\"refresh\"" in metaTags:
            print("%s Meta Tag Redirection" % good)
            metaUrl = re.search(r'url=([^"\']+)', metaTags, re.IGNORECASE)
            results.append({"type": "meta", "request_url": finalUrl, "payload": payload, "status_code": response.status_code, "destination": metaUrl.group(1) if metaUrl else ""})
            return True

        location = response.headers.get('Location')
        print("%s Header Based Redirection : %s %s  %s" % (good, finalUrl, arrow, location))
        results.append({"type": "header", "request_url": finalUrl, "payload": payload, "status_code": response.status_code, "destination": location})

    elif response.status_code == 200:
        if scriptMatch:
            print("%s Javascript Based Redirection" % good)
            results.append({"type": "javascript", "request_url": finalUrl, "payload": payload, "status_code": response.status_code, "sources": sourcesMatch})

            if sourcesMatch is not None:
                print("%s Potentially Vulnerable Source/Sink(s) Found: \033[1m%s\033[00m" % (good, " ".join(sourcesMatch)))
            return True

        if metaTagSearch and "http-equiv=\"refresh\"" in str(response.text):
            print("%s Meta Tag Redirection" % good)
            metaUrl = re.search(r'url=([^"\']+)', str(response.text), re.IGNORECASE)
            results.append({"type": "meta", "request_url": finalUrl, "payload": payload, "status_code": response.status_code, "destination": metaUrl.group(1) if metaUrl else ""})
            return True

        elif "http-equiv=\"refresh\"" in str(response.text) and not metaTagSearch:
            print("%s The page is only getting refreshed" % bad)
            return True

    elif response.status_code in errorCodes:
        print("%s %s [\033[91m%s\033[00m]" % (bad, finalUrl, response.status_code))

    else:
        print("%s Found nothing :: %s" % (bad, finalUrl))


def saveResults() -> None:
    """Write accumulated results to the export file as JSON."""
    if outputFile is not None and not outputFile.closed:
        json.dump(results, outputFile, indent=2)
        outputFile.close()


def main() -> None:
    global args, payloadLines, outputFile
    print("\033[91m\n\tOralyzer\033[00m\n")
    args = parser.parse_args()
    target = args.url

    if (args.payload != DEFAULT_PAYLOAD) and (args.crlf or args.waybacks):
        print("%s '-p' can't be used with '-crlf' or '--wayback'" % bad)
        exit()

    if not (args.url or args.path):
        print('Made by \033[1mr0075h3ll\033[00m')
        print(parser.format_help().lower())

    if not args.crlf and not args.waybacks:
        try:
            with open(args.payload, encoding='utf-8') as payloadFile:
                payloadLines = payloadFile.read().splitlines()
        except FileNotFoundError:
            print("%s Payload file not found" % bad)
            exit()

    if args.path:
        try:
            with open(args.path, encoding='utf-8') as targetFile:
                targets = targetFile.read().splitlines()
        except FileNotFoundError:
            print("%s Target file not found" % bad)
            exit()

    if args.export:
        if os.path.exists(args.export):
            open(args.export, 'w').close()  # erase the content of the file
        outputFile = open(args.export, "a+")
    else:
        outputFile = None

    try:
        if args.url:
            if args.crlf and not args.waybacks:
                crlfScan(target, args.proxy)

            elif args.waybacks and not args.crlf:
                print("%s Getting juicy URLs from archive.org" % info)
                results.extend({"type": "wayback", "target": target, "found_url": u} for u in getUrls(target, "wayback_data.txt"))

            elif not (args.crlf and args.waybacks):
                analyze(target)

        elif args.path:
            if args.crlf and not args.waybacks:
                for target in targets:
                    print("%s Target: %s" % (info, target))
                    crlfScan(target, args.proxy)
                    print("\n")

            elif args.waybacks and not args.crlf:
                print("%s Getting juicy URLs from archive.org" % info)
                for target in targets:
                    print("%s URL: %s" % (info, target))
                    results.extend({"type": "wayback", "target": target, "found_url": u} for u in getUrls(target, "wayback_%d.txt" % random.randint(0, 1000)))
                    print("\n")

            elif not (args.crlf and args.waybacks):
                for target in targets:
                    print("%s Target: \033[92m%s\033[00m" % (info, target))
                    analyze(target)
                    print("\n")

    except KeyboardInterrupt:
        print("\nQuitting...")
    finally:
        saveResults()


if __name__ == "__main__":
    main()
