#!/usr/bin/env python3
"""Basic web/server log analyzer for lab evidence."""

from __future__ import annotations

import argparse
import re
from collections import Counter, defaultdict
from pathlib import Path


IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
STATUS_RE = re.compile(r'"\s(?P<status>\d{3})\s')
REQUEST_RE = re.compile(r'"(?P<method>[A-Z]+)\s(?P<path>\S+)')
SUSPICIOUS_PATTERNS = {
    "sql_injection": re.compile(r"('|%27|union\s+select|or\s+1=1|information_schema)", re.I),
    "xss": re.compile(r"(<script|%3cscript|onerror=|javascript:)", re.I),
    "path_traversal": re.compile(r"(\.\./|%2e%2e%2f|/etc/passwd|boot\.ini)", re.I),
    "command_injection": re.compile(r"(;|\||%7c|&&).*(id|whoami|uname|cat|curl|wget)", re.I),
    "scanner_noise": re.compile(r"(nikto|sqlmap|nmap|gobuster|dirbuster|wpscan)", re.I),
}


def analyze(path: Path) -> tuple[Counter, Counter, Counter, dict[str, list[str]]]:
    ips: Counter[str] = Counter()
    statuses: Counter[str] = Counter()
    paths: Counter[str] = Counter()
    suspicious: dict[str, list[str]] = defaultdict(list)

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            ip_match = IP_RE.search(line)
            if ip_match:
                ips[ip_match.group(0)] += 1

            status_match = STATUS_RE.search(line)
            if status_match:
                statuses[status_match.group("status")] += 1

            request_match = REQUEST_RE.search(line)
            if request_match:
                paths[request_match.group("path")] += 1

            for name, pattern in SUSPICIOUS_PATTERNS.items():
                if pattern.search(line) and len(suspicious[name]) < 10:
                    suspicious[name].append(line.strip())

    return ips, statuses, paths, suspicious


def print_counter(title: str, counter: Counter, limit: int) -> None:
    print(f"\n{title}")
    if not counter:
        print("- None")
        return
    for key, count in counter.most_common(limit):
        print(f"- {key}: {count}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze web/server logs.")
    parser.add_argument("logfile", type=Path, help="Path to log file")
    parser.add_argument("--limit", type=int, default=10, help="Rows per section")
    args = parser.parse_args()

    if not args.logfile.is_file():
        print(f"Log file not found: {args.logfile}")
        return 1

    ips, statuses, paths, suspicious = analyze(args.logfile)
    print(f"Analyzed: {args.logfile}")
    print_counter("Top source IPs", ips, args.limit)
    print_counter("HTTP status codes", statuses, args.limit)
    print_counter("Top requested paths", paths, args.limit)

    print("\nSuspicious indicators")
    if not suspicious:
        print("- None detected")
    for name, lines in suspicious.items():
        print(f"- {name}: {len(lines)} sample(s)")
        for line in lines[:3]:
            print(f"  {line[:240]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

