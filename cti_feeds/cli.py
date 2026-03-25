"""Command-line interface for CTI Feeds Aggregator."""

import argparse
import json
import sys
import logging

from . import __version__
from .aggregator import CTIAggregator, FEEDS


def main():
    parser = argparse.ArgumentParser(
        prog="cti-feeds",
        description="CTI Feeds Aggregator — Aggregate free threat intelligence feeds",
    )
    parser.add_argument("--version", action="version", version=f"cti-feeds {__version__}")
    sub = parser.add_subparsers(dest="command", help="Available commands")

    # ── fetch ──
    fetch_p = sub.add_parser("fetch", help="Fetch CTI feeds")
    fetch_p.add_argument("--all", action="store_true", help="Fetch all feeds")
    fetch_p.add_argument("--feed", type=str, help=f"Specific feed: {', '.join(FEEDS.keys())}")
    fetch_p.add_argument("--format", type=str, default="table", choices=["table", "json", "csv"],
                         help="Output format (default: table)")
    fetch_p.add_argument("--output", "-o", type=str, help="Output file path")
    fetch_p.add_argument("--timeout", type=int, default=30, help="HTTP timeout in seconds")
    fetch_p.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    # ── check ──
    check_p = sub.add_parser("check", help="Check if an IOC is in feeds")
    check_p.add_argument("--ioc", type=str, required=True, help="IOC to check (IP, URL, hash)")
    check_p.add_argument("--verbose", "-v", action="store_true")

    # ── list ──
    sub.add_parser("list", help="List available feeds")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return

    # Setup logging
    level = logging.DEBUG if getattr(args, "verbose", False) else logging.INFO
    logging.basicConfig(level=level, format="%(message)s")

    if args.command == "list":
        _cmd_list()
    elif args.command == "fetch":
        _cmd_fetch(args)
    elif args.command == "check":
        _cmd_check(args)


def _cmd_list():
    print(f"\n{'Feed':<20} {'Provider':<15} {'Description'}")
    print("-" * 75)
    for name, info in FEEDS.items():
        print(f"{name:<20} {info['provider']:<15} {info['description']}")
    print(f"\nTotal: {len(FEEDS)} feeds (all free, no API key required)\n")


def _cmd_fetch(args):
    agg = CTIAggregator(timeout=args.timeout)

    if args.all:
        iocs = agg.fetch_all()
    elif args.feed:
        result = agg.fetch(args.feed)
        iocs = result.iocs
    else:
        print("Error: specify --all or --feed <name>")
        sys.exit(1)

    # Export to file if requested
    if args.output:
        fmt = args.format if args.format != "table" else "json"
        agg.export(args.output, format=fmt)
        print(f"\nExported {len(iocs)} IOCs to {args.output}")
        return

    # Print summary
    summary = agg.summary()
    print(f"\n{'=' * 50}")
    print(f"  CTI Feeds Aggregator — Summary")
    print(f"{'=' * 50}")
    print(f"  Total IOCs:    {summary['total_iocs']:,}")
    print(f"  Feeds OK:      {summary['feeds_ok']}/{summary['feeds_ok'] + summary['feeds_failed']}")
    if summary["by_type"]:
        print(f"\n  By type:")
        for t, c in sorted(summary["by_type"].items(), key=lambda x: -x[1]):
            print(f"    {t:<15} {c:>8,}")
    if summary["by_source"]:
        print(f"\n  By source:")
        for s, c in sorted(summary["by_source"].items(), key=lambda x: -x[1]):
            print(f"    {s:<20} {c:>8,}")
    print(f"{'=' * 50}\n")

    # Output in requested format
    if args.format == "json":
        print(json.dumps([i.to_dict() for i in iocs[:20]], indent=2))
        if len(iocs) > 20:
            print(f"\n... ({len(iocs) - 20} more IOCs, use --output to export all)")


def _cmd_check(args):
    print(f"Fetching all feeds to check IOC: {args.ioc}")
    agg = CTIAggregator()
    agg.fetch_all()

    result = agg.check(args.ioc)
    if result:
        print(f"\n  FOUND — {result.ioc_value}")
        print(f"  Type:       {result.ioc_type.value}")
        print(f"  Threat:     {result.threat_type.value}")
        print(f"  Source:     {result.source}")
        print(f"  Confidence: {result.confidence}%")
        print(f"  Tags:       {', '.join(result.tags)}")
        print(f"  Reference:  {result.reference}")
    else:
        print(f"\n  NOT FOUND in any feed.")
        print(f"  (This does not mean the IOC is safe — only that it's not in current feeds)")


if __name__ == "__main__":
    main()
