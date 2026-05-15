#!/usr/bin/env python3
"""DomainXray — DNS & WHOIS Analysis Tool."""

from __future__ import annotations

import argparse
import json
import sys
import textwrap

from app.inspector import DomainXray
from app.models import DNSResult, WhoisResult, DomainReport

VALID_RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "PTR", "SRV"]

CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def _supports_color() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _c(text: str, code: str) -> str:
    if not _supports_color():
        return text
    return f"{code}{text}{RESET}"


def _print_banner() -> None:
    w = 44
    print(_c("╔" + "═" * w + "╗", DIM))
    print(_c("║" + "DomainXray  v1.0.0".center(w) + "║", BOLD + CYAN))
    print(_c("║" + "DNS & WHOIS Analysis Tool".center(w) + "║", BOLD + CYAN))
    print(_c("╚" + "═" * w + "╝", DIM))
    print()


def _print_dns(result: DNSResult) -> None:
    print(_c("── DNS Records ─────────────────────────", BOLD))
    print(f"   Resolver: {_c(result.resolver, DIM)}")
    print()

    if not result.records and not result.errors:
        print(f"   {_c('No records found.', YELLOW)}")
        return

    for rtype, records in result.records.items():
        print(f"   {_c(rtype, BOLD + GREEN)}")
        for rec in records:
            line = f"     {rec.value}"
            if rec.priority is not None:
                line += f"  (priority: {rec.priority})"
            line += f"  {_c(f'TTL {rec.ttl}', DIM)}"
            print(line)
        print()

    for rtype, err in result.errors.items():
        print(f"   {_c(rtype, BOLD + RED)}  {err}")


def _print_whois(result: WhoisResult) -> None:
    print(_c("── WHOIS Info ──────────────────────────", BOLD))

    if result.error:
        print(f"   {_c('Error:', RED)} {result.error}")
        return

    rows: list[tuple[str, str | None]] = [
        ("Registrar", result.registrar),
        ("WHOIS Server", result.whois_server),
        ("Created", result.creation_date),
        ("Expires", result.expiration_date),
        ("Updated", result.updated_date),
        ("DNSSEC", result.dnssec),
    ]
    for label, value in rows:
        if value:
            print(f"   {label + ':':<16} {value}")

    if result.name_servers:
        print(f"   {'Name Servers:':<16} {', '.join(result.name_servers)}")
    if result.status:
        print(f"   {'Status:':<16} {', '.join(result.status)}")
    if result.emails:
        print(f"   {'Emails:':<16} {', '.join(result.emails)}")
    print()


def _print_report(report: DomainReport) -> None:
    print(f"   Domain: {_c(report.domain, BOLD + CYAN)}")
    print()
    if report.dns:
        _print_dns(report.dns)
        print()
    if report.whois:
        _print_whois(report.whois)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="domainxray",
        description="DNS & WHOIS Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            examples:
              python main.py google.com
              python main.py google.com --dns-only
              python main.py google.com --whois-only
              python main.py google.com -t A AAAA MX
              python main.py google.com --json
              python main.py google.com --resolver 8.8.8.8
              python main.py google.com --whois-only --raw
        """),
    )
    parser.add_argument("domain", help="domain name to inspect")
    parser.add_argument(
        "--dns-only",
        action="store_true",
        help="only perform DNS lookup",
    )
    parser.add_argument(
        "--whois-only",
        action="store_true",
        help="only perform WHOIS lookup",
    )
    parser.add_argument(
        "-t",
        "--type",
        nargs="+",
        choices=VALID_RECORD_TYPES,
        metavar="TYPE",
        help=f"DNS record types to query ({', '.join(VALID_RECORD_TYPES)})",
    )
    parser.add_argument(
        "--resolver",
        help="custom DNS resolver IP (e.g. 8.8.8.8, 1.1.1.1)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="output results as JSON",
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="show raw WHOIS response (with --whois-only)",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    nameservers = [args.resolver] if args.resolver else None
    xray = DomainXray(nameservers=nameservers)

    if not args.json_output:
        _print_banner()

    if args.dns_only and args.whois_only:
        parser.error("--dns-only and --whois-only are mutually exclusive")

    if args.dns_only:
        result = xray.dns_only(args.domain, args.type)
        if args.json_output:
            print(json.dumps(result.to_dict(), indent=2))
        else:
            _print_dns(result)

    elif args.whois_only:
        result = xray.whois_only(args.domain)
        if args.json_output:
            print(json.dumps(result.to_dict(), indent=2))
        elif args.raw:
            print(result.raw)
        else:
            _print_whois(result)

    else:
        report = xray.inspect(args.domain)
        if args.json_output:
            print(report.to_json())
        else:
            _print_report(report)


if __name__ == "__main__":
    main()
