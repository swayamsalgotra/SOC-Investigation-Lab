#!/usr/bin/env python3
"""Analyze TShark-exported DNS CSV for basic investigation indicators."""

import argparse
import csv
from collections import Counter
from pathlib import Path

def truthy(value):
    return str(value).strip().lower() in {"true", "1", "yes"}

def main():
    parser = argparse.ArgumentParser(
        description="Summarize DNS traffic and flag simple investigation heuristics."
    )
    parser.add_argument("csv_file", help="CSV exported by TShark")
    parser.add_argument("--long-name", type=int, default=50,
                        help="Flag query names longer than this many characters")
    parser.add_argument("--output", help="Optional path to save the text summary")
    args = parser.parse_args()

    path = Path(args.csv_file)
    required = {
        "frame.time", "ip.src", "ip.dst", "dns.qry.name",
        "dns.qry.type", "dns.flags.response", "dns.flags.rcode"
    }

    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or not required.issubset(reader.fieldnames):
            raise SystemExit(
                "CSV headers missing or unexpected. Re-export with the project command."
            )
        rows = list(reader)

    queries = [r for r in rows if r["dns.qry.name"].strip()
               and not truthy(r["dns.flags.response"])]
    responses = [r for r in rows if truthy(r["dns.flags.response"])]

    domains = Counter(r["dns.qry.name"].strip().rstrip(".").lower()
                      for r in queries)
    sources = Counter(r["ip.src"].strip() for r in queries if r["ip.src"].strip())
    types = Counter(r["dns.qry.type"].strip() for r in queries
                    if r["dns.qry.type"].strip())

    failures = []
    for row in responses:
        code = row["dns.flags.rcode"].strip()
        if code and code != "0":
            failures.append((row["dns.qry.name"].strip(), code, row["ip.src"].strip()))

    long_names = sorted(
        (name, count) for name, count in domains.items()
        if len(name) > args.long_name
    )
    repeated = sorted(
        (name, count) for name, count in domains.items() if count >= 5
    )

    lines = [
        "DNS TRAFFIC INVESTIGATION SUMMARY",
        "=" * 34,
        f"Input file: {path}",
        f"DNS packets in CSV: {len(rows)}",
        f"Queries: {len(queries)}",
        f"Responses: {len(responses)}",
        f"Unique queried domains: {len(domains)}",
        f"Query source IPs: {len(sources)}",
        "",
        "Query types (TShark numeric codes):",
    ]
    lines += [f"  Type {kind}: {count}" for kind, count in types.most_common()]
    lines += ["", "Most queried domains:"]
    lines += [f"  {name}: {count}" for name, count in domains.most_common(10)]
    lines += ["", f"Non-zero response codes: {len(failures)}"]
    lines += [f"  Domain={name or '(not present)'}, rcode={code}, responder={ip}"
              for name, code, ip in failures]
    lines += ["", f"Long query names (>{args.long_name} characters): {len(long_names)}"]
    lines += [f"  {name}: {count} query/queries" for name, count in long_names]
    lines += ["", f"Repeated domains (5+ queries): {len(repeated)}"]
    lines += [f"  {name}: {count} queries" for name, count in repeated]
    lines += [
        "",
        "INTERPRETATION",
        "These are triage heuristics, not proof of malicious activity.",
        "Non-zero DNS response codes can be legitimate; long names and repetition",
        "need context, a larger baseline, and further investigation.",
    ]

    report = "\n".join(lines)
    print(report)
    if args.output:
        Path(args.output).write_text(report + "\n", encoding="utf-8")
        print(f"\nSummary saved to: {args.output}")

if __name__ == "__main__":
    main()
