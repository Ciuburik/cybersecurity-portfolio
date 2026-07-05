#!/usr/bin/env python3
"""Scan text files for common indicators of compromise."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import re
from pathlib import Path


PATTERNS = {
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "domain": re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"),
    "url": re.compile(r"https?://[^\s\"'<>]+", re.I),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
}


def is_public_ipv4(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.version == 4 and ip.is_global


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def scan_file(path: Path) -> dict[str, set[str]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    results: dict[str, set[str]] = {key: set() for key in PATTERNS}
    for name, pattern in PATTERNS.items():
        results[name].update(match.group(0).rstrip(".,);]") for match in pattern.finditer(text))
    results["ipv4"] = {value for value in results["ipv4"] if is_public_ipv4(value)}
    return results


def iter_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    return [path for path in target.rglob("*") if path.is_file()]


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan files for common IOCs.")
    parser.add_argument("target", type=Path, help="File or directory to scan")
    parser.add_argument("--hash-files", action="store_true", help="Print SHA-256 for each file")
    args = parser.parse_args()

    if not args.target.exists():
        print(f"Target not found: {args.target}")
        return 1

    files = iter_files(args.target)
    if not files:
        print("No files found.")
        return 0

    for path in files:
        try:
            results = scan_file(path)
        except OSError as exc:
            print(f"\n{path}: could not read file: {exc}")
            continue

        has_iocs = any(values for values in results.values())
        if not has_iocs and not args.hash_files:
            continue

        print(f"\n{path}")
        if args.hash_files:
            print(f"sha256_file: {file_hash(path)}")
        for name, values in results.items():
            if values:
                print(f"{name}:")
                for value in sorted(values)[:50]:
                    print(f"- {value}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

