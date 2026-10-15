# Network Threat Detection & SOC Investigation Lab

## Project Overview

This project demonstrates a hands-on Security Operations Center (SOC) investigation workflow using packet analysis, network intrusion detection, and Python-based alert analysis.

The lab uses controlled test traffic to validate custom Suricata detection rules, inspect DNS traffic in Wireshark, analyze IDS alerts, and document findings with supporting evidence.

## Objectives

- Analyze DNS queries and responses using Wireshark.
- Detect selected network activity using custom Suricata rules.
- Investigate a controlled TCP SYN scan against localhost.
- Parse Suricata EVE JSON alerts using Python.
- Generate CSV exports and investigation summaries.
- Preserve packet captures, logs, screenshots, reports, and SHA-256 checksums.

## Tools and Technologies

- **Wireshark** — packet inspection and DNS analysis
- **Suricata** — network intrusion detection and custom alert rules
- **Python 3** — alert parsing, aggregation, and CSV export
- **tcpdump** — packet capture
- **Nmap** — controlled localhost port-scan testing
- **Linux / Kali Linux** — lab environment
- **Git and GitHub** — source control and project documentation

## Project Structure

```text
SOC-Investigation-Lab/
├── alerts/
├── captures/
├── evidence/
│   ├── dns-investigation/
│   ├── first-test/
│   ├── port-scan/
│   └── python-analyzer/
├── reports/
│   └── first-test/
├── rules/
│   └── local.rules
└── scripts/
    └── analyze_alerts.py
```

## Detection and Investigation Scenarios

### 1. HTTP Marker Detection

Generated controlled local HTTP traffic containing a test marker and validated that a custom Suricata rule detected it.

### 2. TCP SYN Scan Detection

Performed a controlled Nmap scan against localhost and tested a custom SYN-threshold rule. The resulting alert was reviewed in Suricata logs and EVE JSON.

The rule is a basic heuristic and may produce false positives. A matching alert does not by itself establish malicious intent.

### 3. DNS Query Detection

Generated a DNS lookup for `example.com`, captured the DNS traffic, and tested a custom Suricata rule.

- **Rule SID:** 1000003
- **Protocol:** DNS over UDP
- **Observed query:** `example.com`
- **Validation:** Matching alert generated

This was a controlled test. The alert is not evidence of malicious DNS activity.

## Python Alert Analyzer

The script `scripts/analyze_alerts.py` reads Suricata EVE JSON events and provides:

- Event and alert counts
- Alert details
- Counts grouped by signature and source IP
- Optional CSV export

Example:

```bash
python3 scripts/analyze_alerts.py alerts/dns-test/eve.json \
  --csv reports/first-test/dns-alerts.csv
```

Use the script's `--help` option to confirm the available arguments.

## Evidence and Reports

The `evidence/` and `reports/` directories contain available packet captures, Suricata logs, JSON events, CSV summaries, investigation reports, and Wireshark screenshots.

The DNS evidence folder includes screenshots for all DNS packets, DNS queries only, and DNS responses only.

SHA-256 checksums are provided in `evidence/dns-investigation/SHA256SUMS` for the files listed in that manifest.

## Limitations

- Tests were conducted in a controlled lab environment.
- Detection rules are simple examples, not a complete production detection system.
- Alerts require context and investigation before being classified as malicious.
- This project does not demonstrate automated blocking or a fully deployed enterprise SIEM.
- Wazuh integration should only be documented after it has been configured and tested.

## Key Learning Outcomes

- Network traffic capture and packet analysis
- DNS query and response inspection
- Signature-based network detection
- IDS alert investigation and triage
- JSON log processing and CSV reporting
- Evidence preservation and incident documentation

## Disclaimer

All tests were performed against controlled lab traffic and localhost systems for educational purposes. Only test systems and networks for which authorization is available should be examined.
