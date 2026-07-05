#!/usr/bin/env python3
"""Simple TCP port scanner for authorised lab targets."""

from __future__ import annotations

import argparse
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993,
    995, 1433, 1521, 1723, 2049, 3306, 3389, 5432, 5900, 5985, 6379, 8080,
    8443, 9200, 9300,
]


def parse_ports(value: str) -> list[int]:
    if value.lower() == "common":
        return COMMON_PORTS

    ports: set[int] = set()
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))

    valid_ports = sorted(port for port in ports if 1 <= port <= 65535)
    if not valid_ports:
        raise argparse.ArgumentTypeError("no valid ports supplied")
    return valid_ports


def scan_port(host: str, port: int, timeout: float) -> tuple[int, bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            try:
                service = socket.getservbyport(port, "tcp")
            except OSError:
                service = "unknown"
            return port, True, service
    except OSError:
        return port, False, ""


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan TCP ports on an authorised lab target."
    )
    parser.add_argument("target", help="IP address or hostname to scan")
    parser.add_argument(
        "-p",
        "--ports",
        type=parse_ports,
        default=COMMON_PORTS,
        help="Ports to scan, for example: common, 22,80,443, 1-1024",
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=1.0, help="Connection timeout in seconds"
    )
    parser.add_argument(
        "-w", "--workers", type=int, default=100, help="Concurrent worker threads"
    )
    args = parser.parse_args()

    print(f"Target: {args.target}")
    print(f"Ports: {len(args.ports)}")
    print()

    open_ports: list[tuple[int, str]] = []
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        futures = {
            executor.submit(scan_port, args.target, port, args.timeout): port
            for port in args.ports
        }
        for future in as_completed(futures):
            port, is_open, service = future.result()
            if is_open:
                open_ports.append((port, service))

    if not open_ports:
        print("No open TCP ports found.")
        return 0

    print("Open TCP ports:")
    for port, service in sorted(open_ports):
        print(f"- {port}/tcp ({service})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

