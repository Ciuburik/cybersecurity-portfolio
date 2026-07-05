#!/usr/bin/env python3
"""Small DNS-based subdomain enumerator for authorised targets."""

from __future__ import annotations

import argparse
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


DEFAULT_WORDLIST = [
    "www", "mail", "webmail", "admin", "portal", "vpn", "dev", "test", "staging",
    "api", "app", "blog", "shop", "secure", "support", "docs", "cdn", "m",
]


def load_words(path: Path | None) -> list[str]:
    if not path:
        return DEFAULT_WORDLIST
    words = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        word = line.strip()
        if word and not word.startswith("#"):
            words.append(word)
    return words


def resolve(name: str) -> tuple[str, list[str]]:
    try:
        _, _, addresses = socket.gethostbyname_ex(name)
        return name, sorted(set(addresses))
    except OSError:
        return name, []


def main() -> int:
    parser = argparse.ArgumentParser(description="Resolve likely subdomains for a domain.")
    parser.add_argument("domain", help="Authorised domain, for example example.com")
    parser.add_argument("-w", "--wordlist", type=Path, help="Optional wordlist file")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Concurrent DNS workers")
    args = parser.parse_args()

    domain = args.domain.strip().strip(".")
    words = load_words(args.wordlist)
    candidates = [f"{word}.{domain}" for word in words]

    print(f"Domain: {domain}")
    print(f"Candidates: {len(candidates)}")
    print()

    found: list[tuple[str, list[str]]] = []
    with ThreadPoolExecutor(max_workers=max(1, args.threads)) as executor:
        futures = {executor.submit(resolve, candidate): candidate for candidate in candidates}
        for future in as_completed(futures):
            name, addresses = future.result()
            if addresses:
                found.append((name, addresses))

    if not found:
        print("No subdomains resolved.")
        return 0

    for name, addresses in sorted(found):
        print(f"{name}: {', '.join(addresses)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

