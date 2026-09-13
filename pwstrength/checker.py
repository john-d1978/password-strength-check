"""Heuristic password strength scoring.

This does not try to be cryptographically rigorous. It combines a rough
entropy estimate (character classes present, times length) with penalties
for patterns that make a password easier to guess than its length and
character set would otherwise suggest: repeated runs, ascending or
descending sequences, keyboard walks, and a short list of passwords that
show up constantly in breach dumps.
"""

from __future__ import annotations

import math
import unicodedata
from dataclasses import dataclass, field

LOWER = "abcdefghijklmnopqrstuvwxyz"
UPPER = LOWER.upper()
DIGITS = "0123456789"

KEYBOARD_ROWS = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
]

# Passwords that sit at the top of essentially every breach-derived
# frequency list. Not exhaustive, just enough to catch the obvious ones.
COMMON_PASSWORDS = {
    "password", "password1", "123456", "123456789", "12345678", "1234567",
    "qwerty", "qwerty123", "111111", "sunshine", "iloveyou", "admin",
    "welcome", "monkey", "login", "abc123", "starwars", "dragon",
    "letmein", "football",
}

LABELS = ["very weak", "weak", "fair", "strong", "very strong"]


@dataclass
class Result:
    password_length: int
    score: int  # 0-4, higher is stronger
    label: str
    reasons: list = field(default_factory=list)

    def __str__(self) -> str:
        lines = [f"{self.label} ({self.score}/4)"]
        for reason in self.reasons:
            lines.append(f"  - {reason}")
        return "\n".join(lines)


def _charset_bits(password: str) -> float:
    """Rough per-character entropy in bits, based on which character
    classes are present anywhere in the password."""
    pool = 0
    if any(c in LOWER for c in password):
        pool += 26
    if any(c in UPPER for c in password):
        pool += 26
    if any(c in DIGITS for c in password):
        pool += 10
    if any(c not in LOWER + UPPER + DIGITS for c in password):
        pool += 33  # printable ASCII punctuation, roughly
    if any(ord(c) > 127 for c in password):
        pool += 32  # non-ASCII widens the effective pool further
    return math.log2(pool) if pool else 0.0


def _longest_run(password: str) -> int:
    """Length of the longest run of one repeated character."""
    if not password:
        return 0
    longest = current = 1
    for prev, cur in zip(password, password[1:]):
        if cur == prev:
            current += 1
            longest = max(longest, current)
        else:
            current = 1
    return longest


def _has_sequence(password: str, run: int = 4) -> bool:
    """True if the password contains an ascending or descending run of
    at least `run` characters, e.g. "abcd" or "4321"."""
    lowered = password.lower()
    for i in range(len(lowered) - run + 1):
        window = lowered[i:i + run]
        codes = [ord(c) for c in window]
        ascending = all(b - a == 1 for a, b in zip(codes, codes[1:]))
        descending = all(a - b == 1 for a, b in zip(codes, codes[1:]))
        if ascending or descending:
            return True
    return False


def _has_keyboard_walk(password: str, run: int = 4) -> bool:
    """True if the password contains a run of adjacent keys from a
    standard QWERTY layout, in either direction."""
    lowered = password.lower()
    for row in KEYBOARD_ROWS:
        for candidate in (row, row[::-1]):
            for i in range(len(candidate) - run + 1):
                if candidate[i:i + run] in lowered:
                    return True
    return False


def assess(password: str) -> Result:
    # Normalize first so visually-identical unicode forms (combining
    # accents vs. precomposed characters) score the same.
    password = unicodedata.normalize("NFC", password)
    length = len(password)

    if length == 0:
        return Result(0, 0, LABELS[0], ["password is empty"])

    reasons = []
    bits = _charset_bits(password) * length

    if length < 8:
        reasons.append(f"only {length} characters; aim for 12 or more")

    longest_run = _longest_run(password)
    if longest_run >= 3:
        reasons.append(
            f"contains a repeated run of {longest_run} identical characters"
        )
        bits -= longest_run * 4

    if _has_sequence(password):
        reasons.append(
            "contains an ascending or descending sequence (e.g. abcd, 4321)"
        )
        bits -= 12

    if _has_keyboard_walk(password):
        reasons.append("contains a keyboard walk (e.g. qwerty, asdf)")
        bits -= 12

    if password.lower() in COMMON_PASSWORDS:
        reasons.append("this is one of the most commonly breached passwords")
        bits = 0.0

    if password.strip("\t\n\r ") == "":
        reasons.append("password is only whitespace")
        bits = 0.0

    unique_chars = len(set(password))
    if unique_chars <= 2 and length >= 4:
        reasons.append("uses only 1-2 distinct characters")
        bits = min(bits, 4.0)

    bits = max(bits, 0.0)

    if bits < 28:
        score = 0
    elif bits < 36:
        score = 1
    elif bits < 60:
        score = 2
    elif bits < 80:
        score = 3
    else:
        score = 4

    if not reasons:
        reasons.append("no obvious weaknesses found")

    return Result(length, score, LABELS[score], reasons)
