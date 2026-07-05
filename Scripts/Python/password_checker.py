#!/usr/bin/env python3
"""Offline password strength checker."""

from __future__ import annotations

import argparse
import getpass
import math
import re


COMMON_PASSWORDS = {
    "password", "password1", "123456", "123456789", "qwerty", "admin",
    "letmein", "welcome", "iloveyou", "monkey", "dragon", "football",
}


def charset_size(password: str) -> int:
    size = 0
    if re.search(r"[a-z]", password):
        size += 26
    if re.search(r"[A-Z]", password):
        size += 26
    if re.search(r"\d", password):
        size += 10
    if re.search(r"[^A-Za-z0-9]", password):
        size += 33
    return max(size, 1)


def score_password(password: str) -> tuple[int, list[str]]:
    score = 0
    feedback: list[str] = []

    if len(password) >= 16:
        score += 35
    elif len(password) >= 12:
        score += 25
    elif len(password) >= 8:
        score += 10
    else:
        feedback.append("Use at least 12 characters; 16+ is better.")

    categories = [
        bool(re.search(r"[a-z]", password)),
        bool(re.search(r"[A-Z]", password)),
        bool(re.search(r"\d", password)),
        bool(re.search(r"[^A-Za-z0-9]", password)),
    ]
    score += sum(categories) * 10
    if sum(categories) < 3:
        feedback.append("Use a mix of lowercase, uppercase, numbers, and symbols.")

    lowered = password.lower()
    if lowered in COMMON_PASSWORDS:
        score -= 40
        feedback.append("Avoid common passwords.")
    if re.search(r"(.)\1{2,}", password):
        score -= 10
        feedback.append("Avoid repeated characters.")
    if re.search(r"(0123|1234|2345|3456|4567|5678|6789|abcd|qwer)", lowered):
        score -= 10
        feedback.append("Avoid obvious keyboard or number sequences.")

    entropy = len(password) * math.log2(charset_size(password))
    if entropy >= 80:
        score += 25
    elif entropy >= 60:
        score += 15
    elif entropy >= 40:
        score += 5
    else:
        feedback.append("Increase length to improve estimated entropy.")

    return max(0, min(score, 100)), feedback


def label(score: int) -> str:
    if score >= 80:
        return "Strong"
    if score >= 60:
        return "Moderate"
    if score >= 40:
        return "Weak"
    return "Very weak"


def main() -> int:
    parser = argparse.ArgumentParser(description="Check password strength offline.")
    parser.add_argument("--password", help="Password to check. Omit to prompt securely.")
    args = parser.parse_args()

    password = args.password or getpass.getpass("Password: ")
    score, feedback = score_password(password)

    print(f"Score: {score}/100")
    print(f"Rating: {label(score)}")
    if feedback:
        print("Recommendations:")
        for item in feedback:
            print(f"- {item}")
    else:
        print("No major issues detected.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

