#!/usr/bin/env python3
"""Look up CVE records from the public NVD API."""

from __future__ import annotations

import argparse
import json
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_json(url: str) -> dict:
    request = Request(url, headers={"User-Agent": "pentest-portfolio-cve-lookup/1.0"})
    with urlopen(request, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def cvss_summary(cve: dict) -> str:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key)
        if values:
            metric = values[0]
            data = metric.get("cvssData", {})
            score = data.get("baseScore", "N/A")
            severity = metric.get("baseSeverity") or data.get("baseSeverity") or "N/A"
            return f"{score} {severity}"
    return "N/A"


def first_english_description(cve: dict) -> str:
    for item in cve.get("descriptions", []):
        if item.get("lang") == "en":
            return item.get("value", "")
    return "No English description available."


def reference_urls(cve: dict) -> list[str]:
    references = cve.get("references", [])
    if isinstance(references, dict):
        references = references.get("referenceData", [])

    urls: list[str] = []
    if isinstance(references, list):
        for ref in references:
            if isinstance(ref, dict) and ref.get("url"):
                urls.append(ref["url"])
    return urls


def print_record(item: dict) -> None:
    cve = item.get("cve", {})
    cve_id = cve.get("id", "Unknown")
    published = cve.get("published", "Unknown")
    modified = cve.get("lastModified", "Unknown")
    description = first_english_description(cve)

    print(f"\n{cve_id}")
    print(f"Published: {published}")
    print(f"Modified:  {modified}")
    print(f"CVSS:      {cvss_summary(cve)}")
    print(f"Summary:   {description}")

    refs = reference_urls(cve)
    if refs:
        print("References:")
        for url in refs[:5]:
            print(f"- {url}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Search CVEs using the NVD API.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--id", help="Exact CVE ID, for example CVE-2021-41773")
    group.add_argument("--keyword", help="Keyword search, for example apache tomcat")
    parser.add_argument("--limit", type=int, default=5, help="Maximum results to display")
    args = parser.parse_args()

    params: dict[str, str | int] = {"resultsPerPage": max(1, min(args.limit, 20))}
    if args.id:
        params["cveId"] = args.id.upper()
    else:
        params["keywordSearch"] = args.keyword

    url = f"{NVD_ENDPOINT}?{urlencode(params)}"
    try:
        data = fetch_json(url)
    except HTTPError as exc:
        print(f"NVD request failed: HTTP {exc.code}", file=sys.stderr)
        return 1
    except URLError as exc:
        print(f"NVD request failed: {exc.reason}", file=sys.stderr)
        return 1
    except TimeoutError:
        print("NVD request timed out.", file=sys.stderr)
        return 1

    results = data.get("vulnerabilities", [])
    if not results:
        print("No CVEs found.")
        return 0

    for item in results[: args.limit]:
        print_record(item)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
