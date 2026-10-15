#!/usr/bin/env python3
"""Summarize Suricata EVE JSON alerts and optionally export them to CSV."""

import argparse
import csv
import json
from collections import Counter
from pathlib import Path

CSV_FIELDS = [
    "timestamp",
    "signature",
    "signature_id",
    "severity",
    "src_ip",
    "src_port",
    "dest_ip",
    "dest_port",
    "category",
    "action",
]


def read_events(path):
    total_events = 0
    alerts = []
    malformed = 0

    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                malformed += 1
                continue

            total_events += 1
            if event.get("event_type") == "alert":
                alerts.append(event)

    return total_events, alerts, malformed


def alert_row(event):
    alert = event.get("alert") or {}
    return {
        "timestamp": event.get("timestamp", ""),
        "signature": alert.get("signature", "Unknown signature"),
        "signature_id": alert.get("signature_id", ""),
        "severity": alert.get("severity", ""),
        "src_ip": event.get("src_ip", ""),
        "src_port": event.get("src_port", ""),
        "dest_ip": event.get("dest_ip", ""),
        "dest_port": event.get("dest_port", ""),
        "category": alert.get("category", ""),
        "action": alert.get("action", event.get("action", "")),
    }


def export_csv(alerts, output_path):
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for event in alerts:
            writer.writerow(alert_row(event))


def print_summary(input_path, total_events, alerts, malformed):
    print("\n=== Suricata SOC Alert Summary ===")
    print(f"Input file:        {input_path}")
    print(f"Valid JSON events: {total_events}")
    print(f"Total alerts:      {len(alerts)}")
    print(f"Malformed lines:   {malformed}")

    if not alerts:
        print("\nNo alert events found.")
        return

    signatures = Counter()
    sources = Counter()

    print("\n--- Alert details ---")
    for event in alerts:
        row = alert_row(event)
        signatures[row["signature"]] += 1
        sources[row["src_ip"] or "Unknown"] += 1

        print(f"\nTime:        {row['timestamp'] or 'Unknown'}")
        print(f"Signature:   {row['signature']}")
        print(f"SID:         {row['signature_id'] or 'Unknown'}")
        print(f"Severity:    {row['severity'] or 'Not provided'}")
        print(f"Source:      {row['src_ip'] or 'Unknown'}:{row['src_port'] or '?'}")
        print(f"Destination: {row['dest_ip'] or 'Unknown'}:{row['dest_port'] or '?'}")

    print("\n--- Alerts by signature ---")
    for signature, count in signatures.most_common():
        print(f"{count:>4}  {signature}")

    print("\n--- Alerts by source IP ---")
    for source, count in sources.most_common():
        print(f"{count:>4}  {source}")


def main():
    parser = argparse.ArgumentParser(
        description="Summarize Suricata EVE JSON alerts and optionally export CSV."
    )
    parser.add_argument("eve_file", type=Path, help="Path to Suricata eve.json")
    parser.add_argument(
        "--csv",
        type=Path,
        help="Optional output path for a CSV alert report",
    )
    args = parser.parse_args()

    if not args.eve_file.is_file():
        parser.error(f"Input file not found: {args.eve_file}")

    total_events, alerts, malformed = read_events(args.eve_file)
    print_summary(args.eve_file, total_events, alerts, malformed)

    if args.csv:
        export_csv(alerts, args.csv)
        print(f"\nCSV report written to: {args.csv}")
        print(f"CSV alert rows: {len(alerts)}")


if __name__ == "__main__":
    main()
