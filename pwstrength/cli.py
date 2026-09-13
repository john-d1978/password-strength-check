"""Command line entry point for pwstrength."""

from __future__ import annotations

import argparse
import getpass
import sys

from .checker import assess


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pwstrength",
        description="Estimate how weak or strong a password is.",
    )
    parser.add_argument(
        "password",
        nargs="?",
        help=(
            "password to check; passing it as an argument leaves it "
            "visible in your shell history, so prefer --stdin or the "
            "interactive prompt for anything real"
        ),
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="read the password from the first line of stdin, unhidden",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.password is not None:
        password = args.password
    elif args.stdin:
        password = sys.stdin.readline().rstrip("\n")
    else:
        password = getpass.getpass("password: ")

    result = assess(password)
    print(result)
    return 0 if result.score >= 2 else 1


if __name__ == "__main__":
    raise SystemExit(main())
