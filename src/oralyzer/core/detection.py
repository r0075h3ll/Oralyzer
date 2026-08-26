"""Response detection for open redirects and CRLF injection."""

import logging
import re
from dataclasses import dataclass
from typing import List, Optional

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

REDIRECT_CODES = range(300, 311)

SOURCES_SINKS = [
    "location.href", "location.hash", "location.search", "location.pathname",
    "document.URL", "window.name", "document.referrer", "document.documentURI",
    "document.baseURI", "document.cookie", "location.hostname",
    "jQuery.globalEval", "eval", "Function", "execScript", "setTimeout",
    "setInterval", "setImmediate", "msSetImmediate", "script.src",
    "script.textContent", "script.text", "script.innerText", "script.innerHTML",
    "script.appendChild", "script.append", "document.write", "document.writeln",
    "jQuery", "jQuery.$", "jQuery.constructor", "jQuery.parseHTML", "jQuery.has",
    "jQuery.init", "jQuery.index", "jQuery.add", "jQuery.append", "jQuery.appendTo",
    "jQuery.after", "jQuery.insertAfter", "jQuery.before", "jQuery.insertBefore",
    "jQuery.html", "jQuery.prepend", "jQuery.prependTo", "jQuery.replaceWith",
    "jQuery.replaceAll", "jQuery.wrap", "jQuery.wrapAll", "jQuery.wrapInner",
    "jQuery.prop.innerHTML", "jQuery.prop.outerHTML", "element.innerHTML",
    "element.outerHTML", "element.insertAdjacentHTML", "iframe.srcdoc",
    "location.replace", "location.assign", "window.open", "iframe.src",
    "javascriptURL", "jQuery.attr.onclick", "jQuery.attr.onmouseover",
    "jQuery.attr.onmousedown", "jQuery.attr.onmouseup", "jQuery.attr.onkeydown",
    "jQuery.attr.onkeypress", "jQuery.attr.onkeyup", "element.setAttribute.onclick",
    "element.setAttribute.onmouseover", "element.setAttribute.onmousedown",
    "element.setAttribute.onmouseup", "element.setAttribute.onkeydown",
    "element.setAttribute.onkeypress", "element.setAttribute.onkeyup",
    "createContextualFragment", "document.implementation.createHTMLDocument",
    "xhr.open", "xhr.send", "fetch", "fetch.body", "xhr.setRequestHeader.name",
    "xhr.setRequestHeader.value", "jQuery.attr.href", "jQuery.attr.src",
    "jQuery.attr.data", "jQuery.attr.action", "jQuery.attr.formaction",
    "jQuery.prop.href", "jQuery.prop.src", "jQuery.prop.data", "jQuery.prop.action",
    "jQuery.prop.formaction", "form.action", "input.formaction", "button.formaction",
    "button.value", "element.setAttribute.href", "element.setAttribute.src",
    "element.setAttribute.data", "element.setAttribute.action",
    "element.setAttribute.formaction", "webdatabase.executeSql", "document.domain",
    "history.pushState", "history.replaceState", "xhr.setRequestHeader", "websocket",
    "anchor.href", "anchor.target", "JSON.parse", "localStorage.setItem.name",
    "localStorage.setItem.value", "sessionStorage.setItem.name",
    "sessionStorage.setItem.value", "element.outerText", "element.innerText",
    "element.textContent", "element.style.cssText", "RegExp", "location.protocol",
    "location.host", "input.value", "input.type", "document.evaluate",
]


@dataclass
class Finding:
    """Represents a detected vulnerability."""
    type: str
    request_url: str
    payload: str
    status_code: int
    destination: Optional[str] = None
    sources: Optional[List[str]] = None

    def to_dict(self) -> dict:
        result = {
            "type": self.type,
            "request_url": self.request_url,
            "payload": self.payload,
            "status_code": self.status_code,
        }
        if self.destination is not None:
            result["destination"] = self.destination
        if self.sources is not None:
            result["sources"] = self.sources
        return result


class ResponseAnalyzer:
    """Analyzes HTTP responses for open redirects and CRLF injection."""

    def __init__(self, payloads: List[str]):
        self.payloads = payloads
        self._payload_regex = re.compile(
            "|".join(re.escape(p) for p in payloads), re.IGNORECASE
        )
        self._sources_regex = re.compile(
            "|".join(re.escape(s) for s in SOURCES_SINKS)
        )

    def analyze_redirect(self, response: requests.Response, payload: str) -> Optional[Finding]:
        """Check response for open redirect vulnerabilities."""
        soup = BeautifulSoup(response.text, "html.parser")
        scripts = str(soup.find_all("script"))
        meta_tags = str(soup.find_all("meta"))

        script_match = self._payload_regex.search(scripts)
        meta_match = self._payload_regex.search(meta_tags)

        request_url = response.request.url or ""

        if response.status_code in REDIRECT_CODES:
            location = response.headers.get("Location", "")

            if meta_match and 'http-equiv="refresh"' in meta_tags:
                meta_url = re.search(r"url=([^\"\']+)", meta_tags, re.IGNORECASE)
                return Finding(
                    type="meta",
                    request_url=request_url,
                    payload=payload,
                    status_code=response.status_code,
                    destination=meta_url.group(1) if meta_url else "",
                )

            if location and self._payload_regex.search(location):
                return Finding(
                    type="header",
                    request_url=request_url,
                    payload=payload,
                    status_code=response.status_code,
                    destination=location,
                )

        if response.status_code == 200:
            if script_match:
                sources = list(dict.fromkeys(self._sources_regex.findall(str(soup))))
                return Finding(
                    type="javascript",
                    request_url=request_url,
                    payload=payload,
                    status_code=response.status_code,
                    sources=sources,
                )

            if meta_match and 'http-equiv="refresh"' in response.text:
                meta_url = re.search(r"url=([^\"\']+)", response.text, re.IGNORECASE)
                return Finding(
                    type="meta",
                    request_url=request_url,
                    payload=payload,
                    status_code=response.status_code,
                    destination=meta_url.group(1) if meta_url else "",
                )

        return None

    def analyze_crlf(self, response: requests.Response, payload: str) -> Optional[Finding]:
        """Check response for CRLF injection."""
        googles = ["https://www.google.com", "http://www.google.com", "google.com", "www.google.com"]

        location = response.headers.get("Location")
        cookie = response.headers.get("Set-Cookie")

        if location in googles or cookie == "name=ch33ms;":
            return Finding(
                type="crlf",
                request_url=response.request.url or "",
                payload=payload,
                status_code=response.status_code,
                destination=location,
            )

        return None
