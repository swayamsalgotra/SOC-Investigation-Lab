# Network Threat Detection & SOC Investigation Lab

## Project Overview

This project demonstrates a hands-on Security Operations Center (SOC) investigation workflow using packet analysis, network intrusion detection, and Python-based event analysis.

The lab uses controlled test traffic to validate custom Suricata detection rules, inspect DNS traffic, analyze IDS alerts, and document findings with supporting evidence.

## Objectives

- Capture and inspect network traffic in PCAP format.
- Analyze DNS queries and responses using TShark and Wireshark.
- Detect selected network activity using custom Suricata rules.
- Investigate a controlled TCP SYN scan against localhost.
- Parse Suricata EVE JSON alerts using Python.
- Export DNS packet metadata to CSV and generate investigation summaries.
- Preserve evidence and verify file integrity with SHA-256 checksums.

## Tools and Technologies

- **Suricata** — network intrusion detection and custom alert rules
- **tcpdump** — packet capture
- **TShark / Wireshark** — packet inspection and DNS field extraction
- **Nmap** — controlled localhost port-scan testing
- **Python 3** — alert analysis, DNS event analysis, and CSV reporting
- **jq** — JSON inspection
- **Kali Linux** — lab environment
- **Git and GitHub** — version control and project documentation

## Project Structure

```text
SOC-Investigation-Lab/
├── captures/
│   ├── dns-pattern-test/
│   └── ...
├── evidence/
│   ├── first-test/
│   ├── port-scan/
│   ├── python-analyzer/
│   ├── dns-investigation/
│   ├── user-agent-investigation/
│   ├── user-agent-negative-test/
│   └── dns-pattern-investigation/
├── reports/
│   └── first-test/
├── rules/
│   └── local.rules
└── scripts/
    ├── analyze_alerts.py
    └── analyze_dns.py
```

`alerts/` contains local Suricata output and is not currently committed to Git.

## Detection and Investigation Scenarios

### 1. HTTP Marker Detection

Generated controlled local HTTP traffic containing `SOC-LAB-TEST` and validated that a custom Suricata rule detected it.

### 2. TCP SYN Scan Detection

Performed a controlled Nmap scan against localhost and tested a custom SYN-threshold rule. The resulting alert was reviewed in Suricata logs and EVE JSON.

The rule is a basic heuristic and may produce false positives. A matching alert does not by itself establish malicious intent.

### 3. DNS Query Detection

Generated a DNS lookup for `example.com`, captured the DNS traffic, and tested a custom Suricata rule.

- **Rule SID:** `1000003`
- **Protocol:** DNS over UDP
- **Observed query:** `example.com`
- **Validation:** Matching alert generated

This was a controlled test, not evidence of malicious DNS activity.

### 4. HTTP User-Agent Detection

Created a custom Suricata rule to detect the test User-Agent string `SOC-LAB-SuspiciousClient`.

- A controlled request containing the test string triggered the rule.
- A separate request using `Mozilla/5.0` did not trigger the custom rule.

These tests validate the specific test cases only; they do not establish general detection accuracy.

### 5. DNS Pattern Analysis

Captured controlled DNS queries for several example and test domains, exported DNS packet fields to CSV with TShark, and analyzed the resulting events using Python.

The DNS analyzer summarizes:

- Query and response counts
- Unique queried domains and query sources
- DNS query types
- Non-zero response codes
- Long query names and repeated domains

The captured sample was small and did not establish malicious DNS activity.

## Python Analysis

### Suricata Alert Analyzer

The script `scripts/analyze_alerts.py` reads Suricata EVE JSON and provides event and alert counts, alert details, groupings by signature and source IP, and optional CSV export.

```bash
python3 scripts/analyze_alerts.py --help
```

Example usage, substituting the actual location of your EVE JSON file:

```bash
python3 scripts/analyze_alerts.py PATH_TO_EVE_JSON \
  --csv reports/first-test/alerts.csv
```

### DNS Traffic Analyzer

The script `scripts/analyze_dns.py` reads DNS fields exported to CSV by TShark and generates a summary.

```bash
python3 scripts/analyze_dns.py \
  captures/dns-pattern-test/dns-events.csv \
  --output reports/first-test/dns-pattern-summary.txt
```

The analyzer uses simple investigative heuristics. Its output supports triage and is not a verdict that traffic is malicious.

## Evidence and Reports

The `captures/`, `evidence/`, and `reports/` directories contain available PCAP files, exported packet metadata, Suricata logs, JSON events, CSV summaries, investigation notes, and screenshots.

Evidence directories include SHA-256 manifests for the files listed in each manifest. To verify the DNS pattern investigation evidence:

```bash
cd evidence/dns-pattern-investigation
sha256sum -c SHA256SUMS
```

Run checksum verification from the directory containing the relevant `SHA256SUMS` file.

## Limitations

- Tests were conducted in a controlled lab environment.
- Several tests use localhost traffic or small DNS samples.
- Detection rules are demonstrations, not a complete production detection system.
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
- Version control for a security investigation project

## Disclaimer

All tests were performed against controlled lab traffic and localhost systems for educational purposes. Only test systems and networks for which authorization is available should be examined.
