"""Basic tests for Oralyzer core functionality."""

import pytest
from pathlib import Path

from oralyzer.core import (
    HttpClient,
    ResponseAnalyzer,
    Finding,
    load_payloads,
    build_test_cases,
)
from oralyzer.scanner import Scanner


class TestFinding:
    """Tests for Finding dataclass."""

    def test_finding_to_dict(self):
        finding = Finding(
            type="header",
            request_url="https://example.com/login?next=//evil.com",
            payload="//evil.com",
            status_code=302,
            destination="https://evil.com",
        )
        result = finding.to_dict()

        assert result["type"] == "header"
        assert result["request_url"] == "https://example.com/login?next=//evil.com"
        assert result["payload"] == "//evil.com"
        assert result["status_code"] == 302
        assert result["destination"] == "https://evil.com"

    def test_finding_with_sources(self):
        finding = Finding(
            type="javascript",
            request_url="https://example.com/",
            payload="test",
            status_code=200,
            sources=["location.href", "document.URL"],
        )
        result = finding.to_dict()

        assert result["sources"] == ["location.href", "document.URL"]


class TestPayloads:
    """Tests for payload loading and generation."""

    def test_load_payloads_default(self):
        payloads = load_payloads()
        assert isinstance(payloads, list)
        assert len(payloads) > 0

    def test_load_payloads_missing_file(self):
        with pytest.raises(FileNotFoundError):
            load_payloads(Path("/nonexistent/payloads.txt"))

    def test_build_test_cases_with_query_params(self):
        url = "https://example.com/login?next=/home"
        payloads = ["//evil.com", "/redirect"]

        result = build_test_cases(url, payloads)

        assert len(result) == 3
        queries, sent, base_url = result
        assert len(queries) > 0
        assert len(sent) > 0
        assert "example.com" in base_url

    def test_build_test_cases_without_query_params(self):
        url = "https://example.com/login"
        payloads = ["//evil.com", "/redirect"]

        result = build_test_cases(url, payloads)

        assert len(result) == 2
        urls, sent = result
        assert len(urls) > 0
        assert len(sent) > 0


class TestHttpClient:
    """Tests for HTTP client."""

    def test_http_client_creation(self):
        client = HttpClient()
        assert client.timeout == 10
        assert client.proxy is None

    def test_http_client_with_proxy(self):
        client = HttpClient(proxy="http://127.0.0.1:8080")
        assert client.proxy == "http://127.0.0.1:8080"

    def test_http_client_custom_timeout(self):
        client = HttpClient(timeout=30)
        assert client.timeout == 30


class TestResponseAnalyzer:
    """Tests for response analyzer."""

    def test_analyzer_creation(self):
        payloads = ["//evil.com", "/redirect"]
        analyzer = ResponseAnalyzer(payloads)
        assert analyzer.payloads == payloads

    def test_analyze_redirect_no_vulnerability(self):
        import requests
        from unittest.mock import Mock

        payloads = ["//evil.com"]
        analyzer = ResponseAnalyzer(payloads)

        mock_response = Mock(spec=requests.Response)
        mock_response.status_code = 200
        mock_response.text = "<html><body>Normal page</body></html>"
        mock_response.request = Mock()
        mock_response.request.url = "https://example.com/"
        mock_response.headers = {}

        result = analyzer.analyze_redirect(mock_response, "//evil.com")
        assert result is None


class TestScanner:
    """Tests for scan orchestration."""

    @staticmethod
    def _mock_response(status_code=200, text="", headers=None):
        import requests
        from unittest.mock import Mock

        response = Mock(spec=requests.Response)
        response.status_code = status_code
        response.text = text
        response.headers = headers or {}
        response.request = Mock()
        response.request.url = "https://example.com/login"
        return response

    def test_scanner_creation(self):
        scanner = Scanner()
        assert scanner.http_client.timeout == 10

    def test_scan_redirect_header_finding(self):
        scanner = Scanner()
        calls = []

        def fake_get(url, params=None, **kwargs):
            calls.append(url)
            if len(calls) == 1:
                return self._mock_response(302, headers={"Location": "//evil.com"})
            return self._mock_response(200, text="<html></html>")

        scanner.http_client.get = fake_get
        findings = scanner.scan_redirect(
            "https://example.com/login?next=/home", ["//evil.com"]
        )

        assert len(findings) == 1
        assert findings[0].type == "header"
        assert findings[0].destination == "//evil.com"
        assert len(calls) == 3  # payload + two host variants

    def test_scan_redirect_limit_stops_early(self):
        scanner = Scanner()

        def fake_get(url, params=None, **kwargs):
            return self._mock_response(302, headers={"Location": "//evil.com"})

        scanner.http_client.get = fake_get
        findings = scanner.scan_redirect(
            "https://example.com/login?next=/home", ["//evil.com"], limit=1
        )

        assert len(findings) == 1

    def test_scan_redirect_filter_type(self):
        scanner = Scanner()

        def fake_get(url, params=None, **kwargs):
            return self._mock_response(200, text="<html></html>")

        scanner.http_client.get = fake_get
        findings = scanner.scan_redirect(
            "https://example.com/login?next=/home",
            ["//evil.com"],
            filter_type="crlf",
        )

        assert findings == []

    def test_scan_redirect_progress_callback(self):
        scanner = Scanner()
        seen = []

        def fake_get(url, params=None, **kwargs):
            return self._mock_response(200, text="<html></html>")

        scanner.http_client.get = fake_get
        findings = scanner.scan_redirect(
            "https://example.com/login?next=/home",
            ["//evil.com"],
            progress_callback=lambda c, t: seen.append((c, t)),
        )

        assert findings == []
        assert seen[-1] == (3, 3)
