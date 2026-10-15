# SOC Investigation: Possible TCP SYN Scan Burst

## Objective
Validate a custom Suricata threshold rule using a controlled localhost
TCP SYN scan pattern and investigate the resulting alert.

## Scope and Method
- Environment: Kali Linux lab
- Target: 127.0.0.1
- PCAP: evidence/port-scan/port-scan.pcap
- IDS: Suricata 8.0.7
- Rule SID: 1000002
- Rule threshold: 8 TCP SYN packets from one source within 10 seconds
- Analysis tools: TShark and the Python Suricata alert analyzer

## Findings
- Capture size: 24 packets, 1,968 bytes.
- Capture duration: approximately 2.14 milliseconds.
- TCP SYN packets without ACK: 11.
- Distinct destination ports among those SYN packets: 11.
- Observed destination ports: 21, 22, 23, 25, 53, 80, 110, 443, 445, 8000, 8080.
- Source IP: 127.0.0.1.
- Suricata generated one matching alert.
- Alert signature: SOC LAB - Possible TCP SYN scan burst.
- Signature ID: 1000002.
- Logged destination: 127.0.0.1:53.
- Severity field: 3.
- Action: allowed.

## Analysis
The PCAP shows a burst of TCP SYN packets without ACK across multiple
destination ports on localhost. This packet pattern is consistent with
the controlled port-scan test.

The custom Suricata rule counts SYN packets from one source within a time
window. It does not independently require unique destination ports.
The destination port recorded in the alert is associated with the packet
that triggered the threshold; it does not mean port 53 was the only or
primary target.

## Assessment
The controlled test successfully generated a Suricata alert, and the
alert was present in the structured EVE JSON output. The PCAP provides
packet-level support for describing this as a simulated localhost
port-scan pattern.

This is lab validation, not evidence of an external attacker or a
compromised system. The alert was allowed/logged rather than blocked.

## Limitations
- Traffic was generated and captured in a controlled localhost lab.
- The threshold rule may alert on legitimate connection bursts.
- A threshold alert alone does not establish malicious intent.
- This test does not demonstrate production monitoring or automated
  prevention.

## Evidence
- PCAP: evidence/port-scan/port-scan.pcap
- Rule: evidence/port-scan/local.rules
- Alert log: evidence/port-scan/fast.log
- EVE JSON: alerts/port-scan-test/eve.json
- Analyzer summary: evidence/python-analyzer/scenario-results/port-scan-test-summary.txt
- Analyzer CSV: evidence/python-analyzer/scenario-results/port-scan-test-alerts.csv
- Evidence checksums: evidence/port-scan/SHA256SUMS

## Outcome
PASS: the controlled SYN-burst test generated the expected custom
Suricata alert. The conclusion is limited to the observed lab evidence.
