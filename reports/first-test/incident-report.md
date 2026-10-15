# SOC Investigation Report 001: Custom HTTP Marker Detection

## Summary
A controlled HTTP request to a local test server triggered a custom
Suricata signature during offline PCAP analysis.

## Environment
- Platform: Kali Linux in VirtualBox
- IDS: Suricata 8.0.7
- Target: 127.0.0.1:8000
- Test marker: SOC-LAB-TEST
- Capture: captures/local-test.pcap

## Evidence
- PCAP: evidence/first-test/local-test.pcap
- Rule: evidence/first-test/local.rules
- Alert: evidence/first-test/fast.log
- Structured event: evidence/first-test/alert-event.json
- Integrity hash: evidence/first-test/SHA256SUMS

## Detection
- Signature ID: 1000001
- Signature: SOC LAB TEST - HTTP marker detected
- Source: 127.0.0.1:33584
- Destination: 127.0.0.1:8000
- Severity: 3
- Action: allowed

## Investigation
The packet capture contained the HTTP request path /SOC-LAB-TEST.
Suricata detected the marker when replaying the PCAP with checksum
checks disabled using -k none.

## Assessment
The detection succeeded in a controlled localhost test. The event
was logged, not blocked. This validates the custom signature and
basic PCAP-to-alert investigation workflow.

## Limitations
This test demonstrates a custom signature match, not detection of a
real attack. The source and destination were both localhost.

## Next Steps
Test additional controlled scenarios, document results, and build
a Python script to summarize Suricata EVE JSON alerts.
