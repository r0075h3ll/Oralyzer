"""Command-line interface for Oralyzer."""

from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path
from typing import List, Optional

from .core import Finding, load_payloads, scan_crlf
from .scanner import Scanner

logger = logging.getLogger(__name__)

# ANSI color codes
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
RESET = "\033[0m"


class OutputFormatter:
    """Handles all console output with optional color and quiet mode."""

    def __init__(self, quiet: bool = False, no_color: bool = False):
        self.quiet = quiet
        self.no_color = no_color

    def _color(self, text: str, color: str) -> str:
        """Wrap text in ANSI color codes if color is enabled."""
        if self.no_color:
            return text
        return f"{color}{text}{RESET}"

    def _print(self, text: str) -> None:
        """Print text if not in quiet mode."""
        if not self.quiet:
            print(text)

    def banner(self) -> None:
        """Print startup banner."""
        self._print("\n  Oralyzer v2.0.0\n")

    def scan_info(
        self,
        target: Optional[str] = None,
        targets_file: Optional[Path] = None,
        target_count: Optional[int] = None,
        payloads: Optional[int] = None,
        timeout: int = 10,
        workers: int = 5,
        mode: Optional[str] = None,
        filter_type: Optional[str] = None,
        proxy: Optional[str] = None,
    ) -> None:
        """Print scan configuration info."""
        if target:
            self._print(f"Target: {target}")
        elif targets_file and target_count:
            self._print(f"Targets:  {target_count} (from {targets_file})")

        if mode:
            self._print(f"Mode:     {mode}")

        if payloads:
            self._print(f"Payloads: {payloads} | Timeout: {timeout}s | Workers: {workers}")

        if filter_type:
            self._print(f"Filter:   {filter_type}")

        if proxy:
            self._print(f"Proxy:    {proxy}")

        self._print("")

    def progress(self, current: int, total: int, message: str = "Testing payloads...") -> None:
        """Print in-place progress counter."""
        if not self.quiet:
            sys.stdout.write(f"\r[{current}/{total}] {message}")
            sys.stdout.flush()

    def clear_progress(self) -> None:
        """Clear the progress line."""
        if not self.quiet:
            sys.stdout.write("\r" + " " * 80 + "\r")
            sys.stdout.flush()

    def finding(self, finding: Finding) -> None:
        """Print a finding with [+] prefix."""
        prefix = self._color("[+]", GREEN)

        if finding.type == "header":
            self._print(f"{prefix} Header redirect")
            self._print(f"    URL: {finding.request_url}")
            self._print(f"    Status: {finding.status_code} | Destination: {finding.destination}")
            self._print(f"    Payload: {finding.payload}")
        elif finding.type == "javascript":
            self._print(f"{prefix} JavaScript redirect")
            self._print(f"    URL: {finding.request_url}")
            sources_str = ", ".join(finding.sources) if finding.sources else "none"
            self._print(f"    Status: {finding.status_code} | Sources: {sources_str}")
            self._print(f"    Payload: {finding.payload}")
        elif finding.type == "meta":
            self._print(f"{prefix} Meta tag redirect")
            self._print(f"    URL: {finding.request_url}")
            self._print(f"    Status: {finding.status_code} | Destination: {finding.destination}")
            self._print(f"    Payload: {finding.payload}")
        elif finding.type == "crlf":
            self._print(f"{prefix} CRLF injection")
            self._print(f"    URL: {finding.request_url}")
            self._print(f"    Status: {finding.status_code} | Payload: {finding.payload}")
        else:
            self._print(f"{prefix} {finding.type}")
            self._print(f"    URL: {finding.request_url}")
            self._print(f"    Payload: {finding.payload}")

        self._print("")

    def error(self, message: str) -> None:
        """Print error message with [-] prefix."""
        prefix = self._color("[-]", RED)
        self._print(f"{prefix} {message}")

    def info(self, message: str) -> None:
        """Print info message."""
        self._print(message)

    def separator(self) -> None:
        """Print separator line."""
        self._print("\n---\n")

    def summary(
        self,
        targets: int,
        requests: int,
        findings: List[Finding],
        duration: float,
        limit_reached: bool = False,
        interrupted: bool = False,
        output_file: Optional[Path] = None,
        urls_found: Optional[int] = None,
    ) -> None:
        """Print scan summary."""
        if interrupted:
            self._print("Scan interrupted")
        elif limit_reached:
            self._print("Scan complete (limit reached)")
        else:
            self._print("Scan complete")

        self._print(f"  Targets:    {targets}")
        self._print(f"  Requests:   {requests}")

        if urls_found is not None:
            self._print(f"  URLs found: {urls_found}")
        else:
            # Count findings by type
            counts: dict[str, int] = {}
            for f in findings:
                counts[f.type] = counts.get(f.type, 0) + 1

            if counts:
                counts_str = ", ".join(f"{count} {ftype}" for ftype, count in counts.items())
                self._print(f"  Findings:   {len(findings)} ({counts_str})")
            else:
                self._print("  Findings:   0")

        # Format duration
        if duration < 60:
            duration_str = f"{duration:.0f}s"
        else:
            minutes = int(duration // 60)
            seconds = int(duration % 60)
            duration_str = f"{minutes}m {seconds}s"

        self._print(f"  Duration:   {duration_str}")

        if output_file:
            self._print(f"\nResults saved to {output_file}")


def setup_logging(verbose: bool = False) -> None:
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(levelname)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Open redirect and CRLF injection scanner", add_help=False
    )

    parser.add_argument(
        "-h", "--help", action="store_true", help="Show this help message and exit"
    )
    parser.add_argument("-u", "--url", help="Scan a single target")
    parser.add_argument(
        "-l", "--list", dest="path", help="Scan multiple targets from a file", type=Path
    )
    parser.add_argument(
        "-p", "--payload", help="Use custom payloads file", type=Path
    )
    parser.add_argument(
        "-o", "--output", help="Export findings to JSON file", type=Path
    )
    parser.add_argument(
        "-crlf", action="store_true", help="Scan for CRLF injection"
    )
    parser.add_argument(
        "--wayback", action="store_true", help="Fetch URLs from archive.org"
    )
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument(
        "--timeout", type=int, default=10, help="Request timeout in seconds"
    )
    parser.add_argument(
        "--workers", type=int, default=5, help="Concurrent workers (default: 5)"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="Only show findings"
    )
    parser.add_argument(
        "--no-color", action="store_true", help="Disable colored output"
    )
    parser.add_argument(
        "--limit", type=int, help="Stop after N findings"
    )
    parser.add_argument(
        "--filter",
        choices=["header", "javascript", "meta", "crlf"],
        help="Only report specific finding types",
    )

    args = parser.parse_args()

    if args.help:
        return args

    if args.timeout < 1:
        parser.error("--timeout must be at least 1")
    if args.workers < 1:
        parser.error("--workers must be at least 1")
    if args.limit is not None and args.limit < 1:
        parser.error("--limit must be at least 1")

    return args


def load_targets(path: Path) -> List[str]:
    """Load target URLs from file."""
    try:
        return path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        logger.error("Target file not found: %s", path)
        sys.exit(1)
    except UnicodeDecodeError:
        logger.error("Target file is not valid UTF-8: %s", path)
        sys.exit(1)


def print_usage(formatter: OutputFormatter) -> None:
    """Print the banner, options, and examples."""
    formatter.banner()
    formatter.info("Open Redirect & CRLF Injection Scanner\n")
    formatter.info("Usage: oralyzer -u <url> [options] | -l <file> [options]\n")
    formatter.info("Options:")
    formatter.info("  -u <url>          Single target")
    formatter.info("  -l <file>         Targets file (one per line)")
    formatter.info("  -p <file>         Custom payloads file")
    formatter.info("  -o <file>         Save findings as JSON")
    formatter.info("  -crlf             CRLF injection scan")
    formatter.info("  --wayback         Wayback URL discovery")
    formatter.info("  --proxy <url>     Proxy (e.g. http://127.0.0.1:8080)")
    formatter.info("  --timeout <n>     Timeout in seconds (default: 10)")
    formatter.info("  --workers <n>     Concurrent workers (default: 5)")
    formatter.info("  --limit <n>       Stop after N findings")
    formatter.info("  --filter <type>   header, javascript, meta, crlf")
    formatter.info("  -q, --quiet       Only findings")
    formatter.info("  --no-color        Disable colors")
    formatter.info("  -v, --verbose     Verbose logging")
    formatter.info("")
    formatter.info("Examples:")
    formatter.info("  oralyzer -u https://example.com")
    formatter.info("  oralyzer -l targets.txt -o out.json --workers 10")
    formatter.info("")


def save_findings(findings: List[dict], output_path: Path) -> None:
    """Save findings to JSON file."""
    import json

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)

    logger.info("Saved %d findings to %s", len(findings), output_path)


def main() -> None:
    """Main entry point."""
    args = parse_args()
    setup_logging(args.verbose)

    formatter = OutputFormatter(quiet=args.quiet, no_color=args.no_color)

    if args.help or not (args.url or args.path):
        print_usage(formatter)
        sys.exit(0)

    if args.payload and (args.crlf or args.wayback):
        formatter.error("'-p' cannot be used with '-crlf' or '--wayback'")
        sys.exit(1)

    scanner = Scanner(proxy=args.proxy, timeout=args.timeout, max_workers=args.workers)

    targets = [args.url] if args.url else load_targets(args.path)
    target_count = len(targets)

    # Determine scan mode
    mode = None
    if args.crlf:
        mode = "CRLF injection scan"
    elif args.wayback:
        mode = "Wayback Machine URL discovery"

    # Print banner and scan info
    formatter.banner()
    formatter.scan_info(
        target=args.url if args.url else None,
        targets_file=Path(args.path) if args.path else None,
        target_count=target_count if not args.url else None,
        payloads=len(load_payloads(args.payload)) if args.payload and not args.crlf and not args.wayback else (13 if args.crlf else None),
        timeout=args.timeout,
        workers=args.workers,
        mode=mode,
        filter_type=args.filter,
        proxy=args.proxy,
    )

    all_findings: List[Finding | dict] = []
    start_time = time.time()
    total_requests = 0
    limit_reached = False
    interrupted = False
    urls_found = 0

    def progress_callback(current: int, total: int) -> None:
        nonlocal total_requests
        total_requests = current
        formatter.progress(current, total)

    try:
        if args.crlf:
            for target in targets:
                if args.limit and len(all_findings) >= args.limit:
                    limit_reached = True
                    break

                formatter.info(f"[1/{target_count}] {target}" if target_count > 1 else "")
                crlf_findings = scan_crlf(
                    target,
                    scanner.http_client,
                    progress_callback=progress_callback,
                )

                for finding in crlf_findings:
                    if args.filter and finding.type != args.filter:
                        continue
                    all_findings.append(finding)
                    formatter.finding(finding)

                    if args.limit and len(all_findings) >= args.limit:
                        limit_reached = True
                        break

        elif args.wayback:
            formatter.info("Querying archive.org...\n")
            for target in targets:
                wayback_findings = scanner.scan_wayback(target)
                urls_found += len(wayback_findings)
                all_findings.extend(wayback_findings)

                if wayback_findings:
                    formatter.info(f"[+] Found {len(wayback_findings)} URLs matching redirect patterns\n")
                    formatter.info("Sample matches:")
                    for wf in wayback_findings[:3]:
                        formatter.info(f"  {wf['found_url']}")
                    if len(wayback_findings) > 3:
                        formatter.info(f"  ... and {len(wayback_findings) - 3} more\n")
                else:
                    formatter.error("No findings")

        else:
            payloads = load_payloads(args.payload) if args.payload else load_payloads()

            if target_count > 1 and scanner.max_workers > 1:
                redirect_findings, empty_targets = scanner.scan_multiple(
                    targets,
                    payloads,
                    progress_callback=progress_callback,
                    limit=args.limit,
                    filter_type=args.filter,
                )
                formatter.clear_progress()
                for finding in redirect_findings:
                    all_findings.append(finding)
                    formatter.finding(finding)
                for target in empty_targets:
                    formatter.error(f"No findings: {target}")
                if args.limit and len(all_findings) >= args.limit:
                    limit_reached = True
            else:
                for i, target in enumerate(targets, 1):
                    if args.limit and len(all_findings) >= args.limit:
                        limit_reached = True
                        break

                    if target_count > 1:
                        formatter.info(f"[{i}/{target_count}] {target}")

                    redirect_findings = scanner.scan_redirect(
                        target,
                        payloads,
                        progress_callback=progress_callback,
                        limit=args.limit - len(all_findings) if args.limit else None,
                        filter_type=args.filter,
                    )

                    formatter.clear_progress()

                    for finding in redirect_findings:
                        all_findings.append(finding)
                        formatter.finding(finding)

                    if not redirect_findings and target_count > 1:
                        formatter.error("No findings")

                    if args.limit and len(all_findings) >= args.limit:
                        limit_reached = True
                        break

    except KeyboardInterrupt:
        interrupted = True
        formatter.clear_progress()
        formatter.info("\nInterrupted by user")

    duration = time.time() - start_time

    # Print summary
    formatter.separator()
    formatter.summary(
        targets=target_count,
        requests=total_requests,
        findings=[f for f in all_findings if isinstance(f, Finding)],
        duration=duration,
        limit_reached=limit_reached,
        interrupted=interrupted,
        output_file=args.output,
        urls_found=urls_found if args.wayback else None,
    )

    # Save results
    if args.output:
        findings_dicts: List[dict] = [
            f.to_dict() if hasattr(f, "to_dict") else f for f in all_findings
        ]
        save_findings(findings_dicts, args.output)


if __name__ == "__main__":
    main()
