"""
Threat Intel Toolkit command line.

    python -m threatintel phish  "http://paypal-verify.tk/login@evil"
    python -m threatintel vt     44d88612fea8a8f36de82e1278abb02f   (needs VT_API_KEY)
    python -m threatintel vt     8.8.8.8 --key YOUR_KEY
"""

from __future__ import annotations

import argparse
import sys

from . import phishing, vt_check


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="threatintel", description="Phishing-URL heuristics + VirusTotal lookups.")
    sub = p.add_subparsers(dest="command", required=True)

    ph = sub.add_parser("phish", help="Heuristic phishing score for a URL (offline).")
    ph.add_argument("url")

    vt = sub.add_parser("vt", help="VirusTotal reputation for a hash/URL/IP/domain.")
    vt.add_argument("indicator")
    vt.add_argument("--key", help="VirusTotal API key (else uses VT_API_KEY env).")
    return p


def main(argv: list | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "phish":
            print(phishing.analyze(args.url).as_text())
        elif args.command == "vt":
            print(vt_check.check(args.indicator, key=args.key).as_text())
    except (ValueError, ConnectionError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
