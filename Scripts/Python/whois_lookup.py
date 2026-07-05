#!/usr/bin/env python3
"""WHOIS/RDAP lookup helper for domains and IP addresses."""

from __future__ import annotations

import argparse
import ipaddress
import json
import shutil
import subprocess
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def rdap_url(query: str) -> str:
    if is_ip(query):
        return f"https://rdap.org/ip/{query}"
    return f"https://rdap.org/domain/{query}"


def run_whois(query: str) -> int:
    whois = shutil.which("whois")
    if not whois:
        return 2
    result = subprocess.run([whois, query], text=True, capture_output=True, check=False)
    if result.stdout:
        print(result.stdout.strip())
    if result.stderr:
        print(result.stderr.strip(), file=sys.stderr)
    return result.returncode


def run_rdap(query: str) -> int:
    request = Request(rdap_url(query), headers={"User-Agent": "pentest-portfolio-whois/1.0"})
    try:
        with urlopen(request, timeout=20) as response:
            data = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        print(f"RDAP request failed: HTTP {exc.code}", file=sys.stderr)
        return 1
    except URLError as exc:
        print(f"RDAP request failed: {exc.reason}", file=sys.stderr)
        return 1

    print(json.dumps(data, indent=2, sort_keys=True))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Look up WHOIS/RDAP data.")
    parser.add_argument("query", help="Domain or IP address")
    parser.add_argument(
        "--rdap",
        action="store_true",
        help="Use public RDAP JSON instead of the local whois command",
    )
    args = parser.parse_args()

    if args.rdap:
        return run_rdap(args.query)

    code = run_whois(args.query)
    if code == 2:
        print("Local whois command not found. Retrying with RDAP JSON...")
        return run_rdap(args.query)
    return code


if __name__ == "__main__":
    raise SystemExit(main())

